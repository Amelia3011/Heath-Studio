const FIREBASE_PROJECT_ID = "heath-studio";
const FIREBASE_API_KEY = "AIzaSyCdBsXYRV6RiACh7X2eiPWvPxszBEZMX6A";
const APP_ID = "heath-studio-dev";
const SITE_ORIGIN = "https://heathstudio.pages.dev/";

async function verifyHitPayHmac(params, salt) {
    const receivedHmac = params.get("hmac");
    if (!receivedHmac || !salt) return false;

    const keys = [];
    for (const key of params.keys()) {
        if (key !== "hmac") keys.push(key);
    }
    keys.sort();

    const payloadString = keys.map(k => `${k}${params.get(k)}`).join("");

    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(salt),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const sigBuffer = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(payloadString));
    const computedHmac = Array.from(new Uint8Array(sigBuffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

    return computedHmac === receivedHmac;
}

async function getFirebaseAuthToken() {
    const res = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Referer": SITE_ORIGIN
            },
            body: JSON.stringify({ returnSecureToken: true })
        }
    );
    const data = await res.json();
    if (!res.ok || !data.idToken) {
        throw new Error("Firebase Anonymous Auth failed");
    }
    return data.idToken;
}

export async function onRequestPost(context) {
    try {
        const rawBody = await context.request.text();
        const params = new URLSearchParams(rawBody);

        // 1. Verify this webhook genuinely came from HitPay
        const salt = context.env.HITPAY_SALT;
        const isValid = await verifyHitPayHmac(params, salt);
        if (!isValid) {
            return new Response("Invalid HMAC signature", { status: 401 });
        }

        // 2. Only deduct stock when payment is completed
        const status = (params.get("status") || "").toLowerCase();
        const orderId = (params.get("reference_number") || "").trim();
        if (status !== "completed" || !orderId) {
            return new Response("OK (ignored)", { status: 200 });
        }

        const baseUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/artifacts/${APP_ID}/public/data`;
        const idToken = await getFirebaseAuthToken();
        const authHeaders = {
            "Authorization": `Bearer ${idToken}`,
            "Content-Type": "application/json"
        };

        // 3. Look up the pending order saved at checkout
        const orderUrl = `${baseUrl}/pending_orders/${encodeURIComponent(orderId)}`;
        const orderRes = await fetch(orderUrl, { headers: authHeaders });
        if (!orderRes.ok) {
            return new Response("Order record not found", { status: 200 });
        }

        const orderDoc = await orderRes.json();
        const alreadyDeducted = orderDoc.fields?.deducted?.booleanValue === true;
        if (alreadyDeducted) {
            return new Response("Already deducted", { status: 200 });
        }

        const itemKeys = (orderDoc.fields?.items?.arrayValue?.values || [])
            .map(v => v.stringValue)
            .filter(Boolean);

        if (itemKeys.length === 0) {
            return new Response("No items to deduct", { status: 200 });
        }

        // 4. Fetch current inventory, subtract purchased items, and save back
        const invUrl = `${baseUrl}/store_metadata/inventory`;
        const invRes = await fetch(invUrl, { headers: authHeaders });
        if (!invRes.ok) {
            throw new Error("Unable to read inventory");
        }

        const invDoc = await invRes.json();
        const invFields = invDoc.fields || {};

        itemKeys.forEach(key => {
            const existing = invFields[key];
            const currentQty = existing
                ? parseInt(existing.integerValue ?? existing.doubleValue ?? "0", 10)
                : 0;
            const newQty = Math.max(0, currentQty - 1);
            invFields[key] = { integerValue: String(newQty) };
        });

        const patchInvRes = await fetch(invUrl, {
            method: "PATCH",
            headers: authHeaders,
            body: JSON.stringify({ fields: invFields })
        });
        if (!patchInvRes.ok) {
            throw new Error("Unable to update inventory");
        }

        // 5. Mark order as deducted so HitPay retries never double-deduct
        await fetch(`${orderUrl}?updateMask.fieldPaths=deducted`, {
            method: "PATCH",
            headers: authHeaders,
            body: JSON.stringify({
                fields: { deducted: { booleanValue: true } }
            })
        });

        return new Response("Stock deducted successfully", { status: 200 });
    } catch (err) {
        return new Response(`Webhook error: ${err.message}`, { status: 500 });
    }
}
