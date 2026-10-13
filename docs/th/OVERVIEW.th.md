# bwoc-gateway — ภาพรวม

> ฉบับภาษาอังกฤษ: [../en/OVERVIEW.en.md](../en/OVERVIEW.en.md)

## ทำไม

agent ที่อยู่คนละที่ (คนละเครื่อง คนละเครือข่าย คนละองค์กร) มักเข้าถึงกันตรง ๆ ไม่ได้ — NAT, firewall, และอินเทอร์เน็ตสาธารณะขวางอยู่ transport ที่มีอยู่แต่ละตัวมีช่องว่างสำหรับเคสนี้:

| Transport | ช่องว่างสำหรับ multi-place |
|---|---|
| **A2A** (HTTP JSON-RPC) | inbound HTTP; default loopback; ไม่ทะลุ NAT; ไม่มี server-push |
| **MQTT** | ต้องมี broker ที่ทั้งสองฝั่งเข้าถึงร่วมกัน; broker กลายเป็น infra ที่ต้องดูแล |
| **peer / routes.toml** | ต้องมี path/address ที่เข้าถึงได้ต่อ peer |

`bwoc-gateway` เพิ่ม **relay ที่ persistent, ผ่านการยืนยันตัวตน, และรู้ presence**: agent แต่ละตัวถือ WebSocket ขาออกหนึ่งเส้นไปยัง gateway แล้ว gateway relay envelope ที่ลงนามแล้วระหว่าง agent ตาม `recipient` เป็นมิตรกับ NAT (ขาออกอย่างเดียว) และ server-push ได้ (gateway ส่งทันทีที่ผู้รับออนไลน์)

## มันคืออะไร — และไม่ใช่อะไร

- **คือ:** rendezvous + relay แบบ optional แมป `agent_id → connection ที่ยังอยู่`; route ตาม `recipient`; ยืนยันตัวตนด้วย signed challenge
- **ไม่ใช่:** trust anchor, registry ของ identity, หรือ hop บังคับ — identity อยู่ที่ keypair, การตัดสิน trust อยู่ที่ harness ฝั่งผู้รับ

## ท่าทีด้านความปลอดภัย (Phase 5 *สังวร* ที่ขอบ)

gateway เป็นพื้นผิว **untrusted-ingress** บนอินเทอร์เน็ตสาธารณะโดยนิยาม จึงสืบทอดวินัยสังวรของ framework:

- **การยืนยันตัวตน = signed challenge** agent ลงนาม nonce ของ server ด้วย ed25519 key; keypair คือ login ไม่มีรหัสผ่าน ไม่มี account ให้ถูกเจาะ
- **ลายเซ็น end-to-end** envelope ลงนามโดย agent *ผู้ส่ง*; gateway ปลอม `sender` ไม่ได้ ผู้รับ verify ลายเซ็นเอง
- **ไม่เชื่อ payload** gateway route ตาม header `recipient` ที่เป็น cleartext เท่านั้น ไม่ตีความหรือรับรอง body (การเข้ารหัส body แบบ E2E — ให้ relay อ่าน payload ไม่ได้ด้วยซ้ำ — มีให้ใช้แล้วใน `gateway-client::crypto`)
- **`sender` เป็นแค่คำอ้าง** relay พิสูจน์ได้ว่า connection ถือ key ที่ยื่นมา แต่ไม่ได้ผูก `agent_id` กับ key และไม่ได้เทียบ `sender` ของ envelope กับ connection มีแต่ลายเซ็นชั้นในเท่านั้นที่ระบุตัวผู้ส่งได้
- **Auto-pong เป็น opt-in และแคบ** `bwoc-gateway-recv --auto-pong` ตอบ `{"type":"ping"}` ด้วย pong รูปแบบตายตัว ไม่ตอบ pong และจำกัดอัตราต่อ sender ที่อ้างมา ไม่รันคำสั่งใด ๆ และไม่เขียน ping/pong ลง inbox
- **การควบคุมที่ขอบ** TLS, rate limit ต่อ agent, queue มีขอบเขต การอนุญาตแบบ capability/Kalyāṇamitta-7 ยังอยู่ที่ harness ฝั่งผู้รับ — gateway ไม่เคยยกระดับ trust

## โรดแมป

1. ✅ **MVP (scaffold):** WS relay + signed-challenge auth + presence + relay ออนไลน์
2. ✅ **store-and-forward** ทนทานสำหรับผู้รับที่ออฟไลน์
3. ✅ **การเข้ารหัส body แบบ end-to-end** (relay route ตาม header อ่าน content ไม่ได้)
4. ✅ การต่อกับ framework: `RouteTarget::Gateway` ใน `routes.toml` + `gateway-client` ที่ harness ขับ (BWOC-Framework 2.28.0)
5. ✅ **federation หลาย gateway** (gateway peer กันเพื่อ relay ข้าม region/องค์กร)
6. ✅ **resource broker** — ครึ่งฝั่ง discovery ของ BWOC Resource Protocol (registry ของ offer แบบ in-memory ที่ evict ตาม TTL; claim/lease วิ่งผ่าน relay)
