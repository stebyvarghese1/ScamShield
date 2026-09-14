"""Cybersecurity Education Engine & Interactive Training Scenarios"""
from typing import List, Dict, Any

SECURITY_TIPS = [
    {
        "id": "tip-1",
        "title": "The Golden Rule: Never Enter A PIN To Receive Money",
        "category": "BANKING",
        "summary": "In digital wallets and UPI, entering your passcode or PIN is EXCLUSIVELY used to deduct money from your account, never to receive it.",
        "action": "If a buyer or stranger asks you to scan a QR code or enter a PIN to receive a payment, immediately terminate communication."
    },
    {
        "id": "tip-2",
        "title": "Inspect the Domain Suffix, Not the Prefix",
        "category": "PHISHING",
        "summary": "Scammers disguise domains like 'paypal.com.account-update.xyz'. The real destination is always determined by the last two segments before the first slash: 'account-update.xyz'.",
        "action": "Always read domain names from right to left before the first single forward slash."
    },
    {
        "id": "tip-3",
        "title": "Artificial Urgency Is The #1 Scammer Weapon",
        "category": "PSYCHOLOGY",
        "summary": "Phrases like 'Account suspended today', 'Arrest warrant issued', or '24-hour deadline' are designed to bypass your logical evaluation.",
        "action": "Whenever you feel sudden panic from an alert, step back for 2 minutes and contact the organization using an independently verified number."
    },
    {
        "id": "tip-4",
        "title": "Beware Of 'Quishing' (QR Code Phishing)",
        "category": "QR_CODES",
        "summary": "Criminals place fraudulent sticker QR codes over legitimate parking meters, restaurant tables, and bike rentals to divert payments to their personal accounts.",
        "action": "Always inspect physical QR codes to check if a sticker was placed on top of the original surface, and check the URL preview before proceeding."
    },
    {
        "id": "tip-5",
        "title": "Delivery Rescheduling Fees Are Almost Always Fake",
        "category": "DELIVERY",
        "summary": "Messages claiming 'USPS / DHL cannot deliver your package due to an incomplete address, click here to pay $1.50' are phishing campaigns harvesting credit card details.",
        "action": "Look up tracking numbers directly on the official postal website, never through SMS links."
    }
]

INTERACTIVE_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "scenario-1",
        "title": "The Urgent Bank Security Freeze",
        "type": "SMS / Text Message",
        "sender": "+1 (844) 928-1920",
        "content": "ALERT from Chase Bank: Unauthorized charge of $482.10 detected. Reply YES to confirm or click https://chase-security-restore.xyz to immediately freeze your card.",
        "options": [
            {
                "id": "opt-a",
                "text": "Click the link immediately to freeze the card before more money is lost.",
                "is_correct": False,
                "explanation": "Dangerous! The domain 'chase-security-restore.xyz' is a phishing page designed to steal your Chase login credentials and 2FA codes."
            },
            {
                "id": "opt-b",
                "text": "Open the official Chase mobile app on your phone or call the phone number on the back of your card.",
                "is_correct": True,
                "explanation": "Correct! Legitimate financial institutions always allow you to manage security directly in your trusted app or via their official customer service line."
            },
            {
                "id": "opt-c",
                "text": "Reply with 'NO' to cancel the transaction.",
                "is_correct": False,
                "explanation": "Replying to unsolicited phishing texts confirms your phone number is active and monitored, leading to more aggressive attacks."
            }
        ]
    },
    {
        "id": "scenario-2",
        "title": "The Work-From-Home Task Recruiter",
        "type": "WhatsApp Message",
        "sender": "Recruiter Elena (+44 7891 234567)",
        "content": "Hi! I am Elena from Global Digital Media. We are hiring part-time remote reviewers. You can earn $200-$500/day by rating YouTube videos. No experience needed. Join our Telegram channel: t.me/fast_tasks_daily to start.",
        "options": [
            {
                "id": "opt-a",
                "text": "Join the Telegram channel to see if it's legitimate.",
                "is_correct": False,
                "explanation": "This is a classic 'Task Scam'. They will pay you $10 for your first 3 tasks to build trust, then demand you deposit $500 of your own money to unlock 'higher commission tasks'."
            },
            {
                "id": "opt-b",
                "text": "Block and report the sender without clicking any links or replying.",
                "is_correct": True,
                "explanation": "Spot on! Real HR recruitment teams never solicit random international numbers on WhatsApp with absurd pay rates for trivial tasks."
            }
        ]
    },
    {
        "id": "scenario-3",
        "title": "The Parking Meter QR Sticker",
        "type": "Physical QR Code",
        "sender": "Downtown Street Parking",
        "content": "Sticker pasted on a municipal parking meter reads: 'Pay parking quickly with mobile app: [QR Code]'. Scanning the QR opens 'https://quick-park-pay.top/meter/901'.",
        "options": [
            {
                "id": "opt-a",
                "text": "Enter your credit card number to pay the $3 parking fee.",
                "is_correct": False,
                "explanation": "High risk! The '.top' domain and physical sticker indicate an attacker slapped their own QR code over the city's meter to steal payment cards."
            },
            {
                "id": "opt-b",
                "text": "Pay using the physical card slot on the meter or the city's official parking app listed in app stores.",
                "is_correct": True,
                "explanation": "Safe move! Municipalities almost always have a recognized app (like ParkMobile or PayByPhone) rather than sketchy one-off websites."
            }
        ]
    }
]

def get_education_tips() -> List[Dict[str, Any]]:
    return SECURITY_TIPS

def get_interactive_scenarios() -> List[Dict[str, Any]]:
    return INTERACTIVE_SCENARIOS
