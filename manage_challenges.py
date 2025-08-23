#!/usr/bin/env python3
"""
Maintenance script to deduplicate challenges and seed new CTF challenges.

Actions:
- Deduplicate challenges by title (keep lowest id), adjust user scores, and delete dependent rows
- Seed a curated list of new, unique challenges (skip if title exists)
"""

from CTF_GAME import app, db, Challenge, Solve, Submission, User, fernet
from sqlalchemy import func


def adjust_scores_and_delete_challenge(challenge: Challenge) -> None:
    """Adjust user scores for solves of a challenge, then delete child rows and the challenge."""
    # Adjust scores based on solves count per user
    solve_counts = (
        db.session.query(Solve.user_id, func.count(Solve.id))
        .filter(Solve.challenge_id == challenge.id)
        .group_by(Solve.user_id)
        .all()
    )
    for user_id, count in solve_counts:
        user = db.session.get(User, user_id)
        if user:
            user.score = max(0, user.score - (challenge.points * int(count)))

    # Delete dependent rows first
    Submission.query.filter(Submission.challenge_id == challenge.id).delete(synchronize_session=False)
    Solve.query.filter(Solve.challenge_id == challenge.id).delete(synchronize_session=False)

    # Delete the challenge itself
    db.session.delete(challenge)


def deduplicate_challenges_by_title() -> int:
    """Remove duplicate challenges by title (keep the one with lowest id). Returns number of deleted duplicates."""
    deleted = 0
    # Find titles with more than one entry
    dup_titles = (
        db.session.query(Challenge.title, func.count(Challenge.id).label("cnt"))
        .group_by(Challenge.title)
        .having(func.count(Challenge.id) > 1)
        .all()
    )
    for (title, _cnt) in dup_titles:
        # Order by id and keep the first
        rows = Challenge.query.filter_by(title=title).order_by(Challenge.id.asc()).all()
        keep = rows[0]
        to_delete = rows[1:]
        for ch in to_delete:
            adjust_scores_and_delete_challenge(ch)
            deleted += 1
    if deleted:
        db.session.commit()
    return deleted


def add_challenge(title: str, description: str, flag: str, points: int) -> bool:
    """Add a challenge if a challenge with the same title does not already exist."""
    existing = Challenge.query.filter_by(title=title).first()
    if existing:
        return False
    encrypted_flag = fernet.encrypt(flag.encode())
    ch = Challenge(title=title, description=description, flag_encrypted=encrypted_flag, points=points)
    db.session.add(ch)
    return True


NEW_CHALLENGES = [
    {
        "title": "HTTP Header Hunt",
        "description": "The flag is hidden in a custom HTTP header. Use your browser devtools or curl to find it.",
        "flag": "flag{hidden_in_headers}",
        "points": 15,
    },
    {
        "title": "Robots Exposed",
        "description": "Crawl the robots.txt and discover a secret path containing the flag.",
        "flag": "flag{robots_reveal_secrets}",
        "points": 10,
    },
    {
        "title": "Cookie Tampering",
        "description": "A cookie stores your role. Tweak it to become admin and retrieve the flag.",
        "flag": "flag{cookie_monster}",
        "points": 25,
    },
    {
        "title": "JWT Weak Secret",
        "description": "The JWT uses a guessable secret. Crack it and forge a token to get the flag.",
        "flag": "flag{jwt_forged}",
        "points": 35,
    },
    {
        "title": "Directory Traversal",
        "description": "A download endpoint is vulnerable. Traverse directories to read the flag file.",
        "flag": "flag{dotdot_win}",
        "points": 30,
    },
    {
        "title": "SSRF Basics",
        "description": "A URL fetcher can access internal services. Use it to request the flag from localhost.",
        "flag": "flag{ssrf_inner_eye}",
        "points": 40,
    },
    {
        "title": "Command Injection",
        "description": "A parameter flows into a shell command. Inject to read the flag.",
        "flag": "flag{shell_shocked}",
        "points": 45,
    },
    {
        "title": "CSRF Token Missing",
        "description": "A state-changing form lacks CSRF protection. Craft a malicious request to set your role and get the flag.",
        "flag": "flag{csrf_caught}",
        "points": 25,
    },
    {
        "title": "Crypto: XOR OTP Reuse",
        "description": "Two messages were encrypted with the same XOR keystream. Recover plaintext and flag.",
        "flag": "flag{xor_key_reused}",
        "points": 35,
    },
    {
        "title": "Crypto: RSA Small e",
        "description": "RSA used e=3 and no padding. Exploit it to retrieve the plaintext flag.",
        "flag": "flag{rsa_small_e}",
        "points": 50,
    },
    {
        "title": "Forensics: EXIF Leak",
        "description": "An image contains EXIF metadata. Extract it to find the flag.",
        "flag": "flag{exif_spills_all}",
        "points": 20,
    },
    {
        "title": "Forensics: PCAP DNS",
        "description": "Inspect DNS queries in the provided PCAP to rebuild the exfiltrated flag.",
        "flag": "flag{dns_tunnels}",
        "points": 40,
    },
    {
        "title": "Reversing: Simple Crackme",
        "description": "Reverse a tiny binary to determine the correct input and reveal the flag.",
        "flag": "flag{crackme_starter}",
        "points": 30,
    },
    {
        "title": "Pwn: Buffer Overflow 101",
        "description": "Overflow the buffer to control execution and print the flag.",
        "flag": "flag{rip_control}",
        "points": 60,
    },
    {
        "title": "Misc: Morse Code",
        "description": "Decode a Morse-encoded audio snippet to recover the flag.",
        "flag": "flag{dit_dah_win}",
        "points": 15,
    },
    {
        "title": "OSINT: Social Post",
        "description": "A developer leaked the flag in a public social media image. Find it.",
        "flag": "flag{public_leak}",
        "points": 25,
    },
    {
        "title": "Stego: PNG LSB",
        "description": "A PNG hides data using LSB steganography. Extract the hidden flag.",
        "flag": "flag{lsb_hidden}",
        "points": 35,
    },
    {
        "title": "Web: SSTI",
        "description": "The template engine evaluates user input. Exploit SSTI to read the flag.",
        "flag": "flag{ssti_template}",
        "points": 45,
    },
    {
        "title": "Encoding: Double URL Encode",
        "description": "A filter decodes once. Double-encode your payload to bypass and access the flag.",
        "flag": "flag{double_trouble}",
        "points": 20,
    },
    {
        "title": "Network: Port Scan Analysis",
        "description": "Analyze a scan report to determine the service leaking the flag.",
        "flag": "flag{open_ports_open_secrets}",
        "points": 30,
    },
]


def seed_new_challenges() -> int:
    added = 0
    for ch in NEW_CHALLENGES:
        if add_challenge(ch["title"], ch["description"], ch["flag"], ch["points"]):
            added += 1
    if added:
        db.session.commit()
    return added


# Additional curated challenges to broaden coverage
EXTRA_CHALLENGES = [
    {"title": "Web: SQLi Boolean-Based", "description": "Infer data using boolean-based SQL injection.", "flag": "flag{sqli_boolean_l33k}", "points": 35},
    {"title": "Web: SQLi Time-Based", "description": "Use time delays to extract the flag.", "flag": "flag{sqli_time_truth}", "points": 40},
    {"title": "Web: File Upload Bypass", "description": "Bypass extension checks to upload a webshell and read the flag.", "flag": "flag{upload_gotcha}", "points": 50},
    {"title": "Web: IDOR", "description": "An object id is predictable. Access another user's resource to get the flag.", "flag": "flag{idor_exposed}", "points": 25},
    {"title": "Web: Open Redirect", "description": "Chain an open redirect to steal a token and claim the flag.", "flag": "flag{redirect_rider}", "points": 20},
    {"title": "Crypto: Vigenere", "description": "Break a Vigenere cipher to retrieve the flag.", "flag": "flag{vigenere_broken}", "points": 25},
    {"title": "Crypto: Padding Oracle", "description": "Exploit a padding oracle to decrypt the ciphertext and reveal the flag.", "flag": "flag{cbc_padding_oracle}", "points": 60},
    {"title": "Crypto: LCG Predict", "description": "Predict a linear congruential generator to recover the secret flag.", "flag": "flag{predictable_rng}", "points": 45},
    {"title": "Reversing: Packed Binary", "description": "Unpack a binary and find where the flag is checked.", "flag": "flag{unpacked_truth}", "points": 40},
    {"title": "Reversing: Android APK", "description": "Decompile an APK and extract the hardcoded flag.", "flag": "flag{smali_snoop}", "points": 35},
    {"title": "Pwn: Format String", "description": "Exploit a format string bug to read the flag from memory.", "flag": "flag{percent_pwn}", "points": 65},
    {"title": "Pwn: Use-After-Free", "description": "Exploit a UAF to control a function pointer and print the flag.", "flag": "flag{uaf_master}", "points": 70},
    {"title": "Forensics: Memory Dump", "description": "Analyze a memory dump to recover a secret and the flag.", "flag": "flag{memdump_treasure}", "points": 50},
    {"title": "Forensics: PDF JS", "description": "A PDF contains obfuscated JavaScript. Deobfuscate it to get the flag.", "flag": "flag{pdf_js_magic}", "points": 30},
    {"title": "Stego: Audio Spectrogram", "description": "The spectrogram of an audio file hides the flag text.", "flag": "flag{hear_to_see}", "points": 25},
    {"title": "OSINT: Whois Trail", "description": "A domain registration reveals a pastebin link with the flag.", "flag": "flag{whois_clue}", "points": 20},
    {"title": "OSINT: Git History", "description": "An old commit accidentally leaked the flag.", "flag": "flag{git_time_machine}", "points": 30},
    {"title": "Cloud: Misconfigured S3", "description": "A public S3 bucket contains the flag.", "flag": "flag{s3_open_door}", "points": 25},
    {"title": "Cloud: Metadata SSRF", "description": "Exploit SSRF to reach cloud instance metadata and extract the flag.", "flag": "flag{169_254_169_254}", "points": 55},
    {"title": "Misc: QR Code", "description": "Decode a damaged QR code to get the flag.", "flag": "flag{qr_restored}", "points": 15},
]


def seed_extra_challenges() -> int:
    added = 0
    for ch in EXTRA_CHALLENGES:
        if add_challenge(ch["title"], ch["description"], ch["flag"], ch["points"]):
            added += 1
    if added:
        db.session.commit()
    return added


def ensure_minimum_challenges(target_total: int = 50) -> int:
    """Top up with auto-generated practice challenges until target_total is reached. Returns number added."""
    added = 0
    current_total = Challenge.query.count()
    idx = 1
    while current_total < target_total:
        title = f"Practice Challenge #{current_total + 1}"
        if not Challenge.query.filter_by(title=title).first():
            description = "A practice challenge to hone your CTF skills. Solve to earn points."
            flag = f"flag{{auto_gen_{current_total + 1}}}"
            points = 10 + (idx % 7) * 5  # 10..40
            db.session.add(Challenge(title=title, description=description, flag_encrypted=fernet.encrypt(flag.encode()), points=points))
            added += 1
            current_total += 1
            idx += 1
        else:
            # If title somehow exists, just advance to avoid infinite loop
            idx += 1
            current_total = Challenge.query.count()
    if added:
        db.session.commit()
    return added


def trim_challenges_to_target(target_total: int = 50) -> int:
    """Reduce total challenges down to target_total by deleting newest ones first,
    preferring challenges with zero solves, then adjusting scores if needed.
    Returns number of deleted challenges.
    """
    deleted = 0
    total = Challenge.query.count()
    if total <= target_total:
        return 0
    to_remove = total - target_total

    # Get solve counts per challenge
    counts = (
        db.session.query(Challenge.id, func.count(Solve.id).label('solve_count'))
        .outerjoin(Solve, Solve.challenge_id == Challenge.id)
        .group_by(Challenge.id)
        .all()
    )
    # Sort by (solve_count asc, id desc) so we prefer unsolved newest challenges
    counts.sort(key=lambda x: (int(x[1]), int(x[0]) * -1))

    for ch_id, solve_count in counts:
        if to_remove <= 0:
            break
        ch = db.session.get(Challenge, ch_id)
        if not ch:
            continue
        if int(solve_count) == 0:
            # No solves: safe to delete without score adjustments
            Submission.query.filter(Submission.challenge_id == ch.id).delete(synchronize_session=False)
            Solve.query.filter(Solve.challenge_id == ch.id).delete(synchronize_session=False)
            db.session.delete(ch)
            deleted += 1
            to_remove -= 1

    # If still need to remove, delete with score adjustments (fewest solves first)
    if to_remove > 0:
        # Recompute remaining (exclude already deleted via session)
        remaining = (
            db.session.query(Challenge.id, func.count(Solve.id).label('solve_count'))
            .outerjoin(Solve, Solve.challenge_id == Challenge.id)
            .group_by(Challenge.id)
            .all()
        )
        remaining.sort(key=lambda x: (int(x[1]), int(x[0]) * -1))
        for ch_id, _cnt in remaining:
            if to_remove <= 0:
                break
            ch = db.session.get(Challenge, ch_id)
            if not ch:
                continue
            adjust_scores_and_delete_challenge(ch)
            deleted += 1
            to_remove -= 1

    if deleted:
        db.session.commit()
    return deleted


if __name__ == "__main__":
    with app.app_context():
        print("Deduplicating challenges by title...")
        removed = deduplicate_challenges_by_title()
        print(f"Removed {removed} duplicate challenge(s)")

        print("Seeding curated unique challenges...")
        added_a = seed_new_challenges()
        added_b = seed_extra_challenges()
        print(f"Added {added_a + added_b} curated challenge(s)")

        print("Ensuring at least 50 total challenges...")
        topped_up = ensure_minimum_challenges(50)
        total = Challenge.query.count()
        print(f"Topped up with {topped_up} challenge(s). Total before trim: {total}")

        if total > 50:
            print("Trimming down to exactly 50 challenges...")
            removed = trim_challenges_to_target(50)
            total = Challenge.query.count()
            print(f"Removed {removed} challenge(s). Total challenges now: {total}")
        else:
            print(f"Total challenges now: {total}")


