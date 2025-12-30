from fastapi import FastAPI, Request

app = FastAPI(title="P3 Attack Log Receiver")

@app.post("/log-attack")
async def log_attack(request: Request):
    attack_data = await request.json()

    print("\n🔴 NEW ATTACK LOG RECEIVED 🔴")
    print(attack_data)

    return {"status": "log_saved", "received_data": attack_data}
