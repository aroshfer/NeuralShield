#!/usr/bin/env python3

import asyncio
import json
import time
import uuid
import os
import logging

from aiohttp import web, WSMsgType
from collections import deque
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

PORT = int(os.environ.get("PORT", 10000))

TOKEN = os.getenv("NS_TOKEN", "dev-token")

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger("NeuralShield")

# ─────────────────────────────────────────────
# MEMORY STORAGE
# ─────────────────────────────────────────────

agents = {}
agent_ws = {}
host_to_id = {}

events = deque(maxlen=50000)
alerts = deque(maxlen=5000)

dash_clients = set()

# ─────────────────────────────────────────────
# RISKY TOOLS
# ─────────────────────────────────────────────

RISKY = {
    "mimikatz",
    "meterpreter",
    "nc.exe",
    "ncat",
    "psexec",
    "hydra",
    "sqlmap",
    "nmap",
    "masscan",
    "msfconsole",
    "msfvenom"
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def tnow():
    return datetime.now(timezone.utc).isoformat()

def sev(score):

    if score >= 0.85:
        return "critical"

    if score >= 0.65:
        return "high"

    if score >= 0.40:
        return "medium"

    return "low"

# ─────────────────────────────────────────────
# EVENT SCORING
# ─────────────────────────────────────────────

def score_event(ev):

    score = 0.0

    process = (ev.get("process") or "").lower()
    cmdline = (ev.get("cmdline") or "").lower()

    if any(x in process for x in RISKY):
        score += 0.70

    if "-enc " in cmdline:
        score += 0.60

    if "downloadstring" in cmdline:
        score += 0.60

    if "iex(" in cmdline:
        score += 0.60

    if "mimikatz" in cmdline:
        score += 1.00

    return round(min(score, 1.0), 3)

# ─────────────────────────────────────────────
# BROADCAST
# ─────────────────────────────────────────────

async def broadcast(msg):

    dead = set()

    for ws in list(dash_clients):

        try:
            await ws.send_json(msg)

        except:
            dead.add(ws)

    dash_clients.difference_update(dead)

# ─────────────────────────────────────────────
# AGENT WEBSOCKET
# ─────────────────────────────────────────────

async def agent_handler(request):

    ws = web.WebSocketResponse()

    await ws.prepare(request)

    agent_id = None

    try:

        async for msg in ws:

            if msg.type == WSMsgType.TEXT:

                try:
                    data = json.loads(msg.data)

                except:
                    continue

                t = data.get("type")

                # ─────────────────────────────
                # ENROLL
                # ─────────────────────────────

                if t == "enroll":

                    if data.get("token") != TOKEN:

                        await ws.send_json({
                            "type": "error",
                            "msg": "Invalid token"
                        })

                        continue

                    hostname = data.get("hostname", "?")
                    ip = data.get("ip", "?")

                    key = f"{hostname}|{ip}"

                    if key in host_to_id:

                        agent_id = host_to_id[key]

                    else:

                        agent_id = str(uuid.uuid4())

                        host_to_id[key] = agent_id

                    agents[agent_id] = {

                        "agent_id": agent_id,
                        "hostname": hostname,
                        "ip": ip,
                        "online": True,
                        "last_seen": time.time(),
                        "events_today": 0,
                        "threats_today": 0,
                        "enrolled_at": tnow()
                    }

                    agent_ws[agent_id] = ws

                    log.info(f"Agent enrolled: {hostname}")

                    await ws.send_json({

                        "type": "enrolled",
                        "agent_id": agent_id
                    })

                    await broadcast({

                        "type": "agent_update",
                        "agents": list(agents.values())
                    })

                # ─────────────────────────────
                # EVENT
                # ─────────────────────────────

                elif t == "event" and agent_id:

                    ev = data.get("data", {})

                    ev["agent_id"] = agent_id
                    ev["received_at"] = tnow()

                    ev["score"] = score_event(ev)

                    events.appendleft(ev)

                    agents[agent_id]["events_today"] += 1

                    await broadcast({

                        "type": "event",
                        "event": ev
                    })

                    if ev["score"] >= 0.40:

                        alert = {

                            "id": f"ALERT-{uuid.uuid4().hex[:8]}",
                            "severity": sev(ev["score"]),
                            "score": ev["score"],
                            "event": ev,
                            "time": tnow()
                        }

                        alerts.appendleft(alert)

                        agents[agent_id]["threats_today"] += 1

                        await broadcast({

                            "type": "alert",
                            "alert": alert
                        })

                # ─────────────────────────────
                # HEARTBEAT
                # ─────────────────────────────

                elif t == "heartbeat" and agent_id:

                    agents[agent_id]["last_seen"] = time.time()

                    await ws.send_json({
                        "type": "ack"
                    })

    except Exception as e:

        log.error(f"agent_handler: {e}")

    finally:

        if agent_id in agents:

            agents[agent_id]["online"] = False

            agent_ws.pop(agent_id, None)

            await broadcast({

                "type": "agent_update",
                "agents": list(agents.values())
            })

    return ws

# ─────────────────────────────────────────────
# DASHBOARD WEBSOCKET
# ─────────────────────────────────────────────

async def dashboard_handler(request):

    ws = web.WebSocketResponse()

    await ws.prepare(request)

    dash_clients.add(ws)

    try:

        await ws.send_json({

            "type": "init",
            "agents": list(agents.values()),
            "alerts": list(alerts),
            "events": list(events)[:100]
        })

        async for msg in ws:

            if msg.type == WSMsgType.TEXT:

                try:
                    data = json.loads(msg.data)

                except:
                    continue

                if data.get("cmd") == "get_agents":

                    await ws.send_json({

                        "type": "agents",
                        "agents": list(agents.values())
                    })

    except Exception as e:

        log.error(f"dashboard_handler: {e}")

    finally:

        dash_clients.discard(ws)

    return ws

# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

async def health(request):

    return web.json_response({

        "ok": True,
        "service": "NeuralShield",
        "agents": len(agents),
        "online": sum(
            1 for a in agents.values()
            if a.get("online")
        )
    })

async def api_agents(request):
    return web.json_response(list(agents.values()))

async def api_alerts(request):
    return web.json_response(list(alerts))

async def api_events(request):
    return web.json_response(list(events)[:1000])

# ─────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────

@web.middleware
async def cors(request, handler):

    if request.method == "OPTIONS":

        return web.Response(headers={

            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "*"
        })

    response = await handler(request)

    response.headers["Access-Control-Allow-Origin"] = "*"

    return response

# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────

def create_app():

    app = web.Application(middlewares=[cors])

    # websocket routes
    app.router.add_get("/agent", agent_handler)
    app.router.add_get("/dashboard", dashboard_handler)

    # api routes
    app.router.add_get("/health", health)
    app.router.add_get("/api/agents", api_agents)
    app.router.add_get("/api/alerts", api_alerts)
    app.router.add_get("/api/events", api_events)

    return app

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

async def main():

    app = create_app()

    runner = web.AppRunner(app)

    await runner.setup()

    site = web.TCPSite(
        runner,
        "0.0.0.0",
        PORT
    )

    await site.start()

    print("\n" + "=" * 50)
    print(" NeuralShield EDR/XDR Server")
    print("=" * 50)
    print(f" Running on port {PORT}")
    print("=" * 50 + "\n")

    while True:
        await asyncio.sleep(3600)

# ─────────────────────────────────────────────
# START
# ─────────────────────────────────────────────

if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("Stopped.")