#!/usr/bin/env python3
"""
Seed Challenges Script for CTF Application
"""

from CTF_GAME import db, Challenge, fernet, app

# Suggested defaults by title to assign category/difficulty automatically when not provided
TITLE_METADATA = {
    "Basic Web Challenge": ("web", "easy"),
    "Decode Me": ("crypto", "easy"),
    "Crypto 101": ("crypto", "easy"),
    "Reverse Engineering": ("re", "easy"),
    "Binary Challenge": ("misc", "easy"),
    "Hidden in Plain Sight": ("web", "easy"),
    "Steganography Image": ("forensics", "medium"),
    "SQL Injection": ("web", "medium"),
    "XSS Attack": ("web", "easy"),
    "Obfuscated JS": ("web", "medium"),
    "Logic Puzzle": ("misc", "easy"),
    "Trivia: CTF History": ("misc", "easy"),
    "Forensics: PCAP Analysis": ("forensics", "medium"),
    "Password Cracking": ("crypto", "easy"),
    "Regex Master": ("misc", "easy"),
    "Network Trivia": ("misc", "easy"),
    "Encoding Chain": ("crypto", "medium"),
    "Zip Bomb": ("forensics", "medium"),
    "Classic Caesar": ("crypto", "easy"),
    "Trivia: RFC 1918": ("misc", "easy"),
    "OSINT: Company Careers": ("osint", "easy"),
    "Web Headers": ("web", "easy"),
    "Robots Exposed": ("web", "easy"),
    "Directory Bruteforce": ("web", "medium"),
    "JWT 101": ("web", "medium"),
    "JWT Key Leak": ("web", "medium"),
    "SQL Boolean-Based": ("web", "hard"),
    "SQL Time-Based": ("web", "hard"),
    "Path Traversal": ("web", "medium"),
    "LFI with PHP Wrappers": ("web", "hard"),
    "Command Injection": ("web", "hard"),
    "XXE Basics": ("web", "medium"),
    "SSRF Metadata": ("web", "hard"),
    "Subdomain Takeover": ("web", "medium"),
    "Weak RSA": ("crypto", "hard"),
    "RSA Common Modulus": ("crypto", "hard"),
    "Vigenere": ("crypto", "medium"),
    "Playfair": ("crypto", "medium"),
    "Rail Fence": ("crypto", "easy"),
    "XOR Single-Byte": ("crypto", "medium"),
    "XOR Repeating": ("crypto", "hard"),
    "PNG LSB Stego": ("forensics", "medium"),
    "WAV Spectrogram": ("forensics", "easy"),
    "PCAP DNS Exfil": ("forensics", "medium"),
    "PCAP HTTP Chunked": ("forensics", "easy"),
    "ELF Strings": ("re", "easy"),
    "ELF Patching": ("re", "hard"),
    "Python Bytecode": ("re", "medium"),
    "Java Reversing": ("re", "medium"),
    "Buffer Overflow 1": ("pwn", "hard"),
    "Format String": ("pwn", "hard"),
    "ROP Gadgets": ("pwn", "insane"),
    "Heap Use-After-Free": ("pwn", "insane"),
    "Zlib Inflate": ("misc", "easy"),
    "Base85": ("misc", "easy"),
    "URL Encoding Chain": ("web", "easy"),
    "Hex + ROT": ("crypto", "easy"),
    "Git Leak": ("misc", "medium"),
    "S3 Bucket": ("misc", "medium"),
    "CORS Misconfig": ("web", "hard"),
    "HTTP Request Smuggling": ("web", "insane"),
    "Padding Oracle": ("crypto", "insane"),
    "JWT Kid Confusion": ("web", "hard"),
    "Zip Password": ("forensics", "medium"),
    "PDF Hidden Layer": ("forensics", "medium"),
    "Excel Macro": ("forensics", "medium"),
    "Android APK": ("re", "medium"),
    "iOS Plist": ("forensics", "medium"),
    "Kerberoasting": ("misc", "insane"),
    "Linux Forensics": ("forensics", "easy"),
    "Windows Registry": ("forensics", "easy"),
    "Memory Dump": ("forensics", "hard"),
    "Docker Misconfig": ("misc", "hard"),
    "Kubernetes Secret": ("misc", "hard"),
    "Cron Injection": ("misc", "hard"),
    "Weak PRNG": ("crypto", "hard"),
}

def add_challenge(title, description, flag, points, category=None, difficulty=None):
    """Add a challenge to the database if the title is unique (uses app Fernet).

    Category and difficulty can be provided; if omitted, they are inferred from TITLE_METADATA or defaulted.
    """
    existing = Challenge.query.filter_by(title=title).first()
    if existing:
        print(f"ℹ️  Skipped (exists): {title}")
        return existing
    # Infer category/difficulty when not provided
    if not category or not difficulty:
        inferred_cat, inferred_diff = TITLE_METADATA.get(title, (category or 'misc', difficulty or 'easy'))
        category = category or inferred_cat
        difficulty = difficulty or inferred_diff
    encrypted_flag = fernet.encrypt(flag.encode())
    challenge = Challenge(
        title=title,
        description=description,
        flag_encrypted=encrypted_flag,
        points=points,
        category=category,
        difficulty=difficulty
    )
    db.session.add(challenge)
    db.session.commit()
    print(f"✅ Added challenge: {title}")

def create_admin_user():
    """Create an admin user for managing challenges"""
    from CTF_GAME import User
    from werkzeug.security import generate_password_hash
    
    # Check if admin user already exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='mukherjeetojo4@gmail.com',
            password_hash=generate_password_hash('TOJO123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Created admin user:")
        print("   Username: admin")
        print("   Password: TOJO123")
        print("   Email: mukherjeetojo4@gmail.com")
    else:
        print("ℹ️  Admin user already exists")

def seed_challenges():
    """Add initial challenges to the database"""
    
    challenges = [
        {
            "title": "Basic Web Challenge",
            "description": "Find the flag hidden in the HTML comments. Look carefully at the page source!",
            "flag": "flag{web_easy_123}",
            "points": 10
        },
        {
            "title": "Decode Me",
            "description": "This text looks strange: ZmxhZ3tzdXBlcl9iYXNlNjR9. Can you decode it?",
            "flag": "flag{super_base64}",
            "points": 20
        },
        {
            "title": "Crypto 101",
            "description": "Decrypt the message: U2ltcGxlIGNyeXB0bw==. Hint: It's base64 encoded!",
            "flag": "flag{simple_crypto}",
            "points": 15
        },
        {
            "title": "Reverse Engineering",
            "description": "What does this reversed text say? '3m4g_gn1rts_3ht_3srever'",
            "flag": "flag{reverse_this_string}",
            "points": 25
        },
        {
            "title": "Binary Challenge",
            "description": "Convert this binary to text: 01100110 01101100 01100001 01100111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101",
            "flag": "flag{binary}",
            "points": 30
        },
        {
            "title": "Hidden in Plain Sight",
            "description": "Sometimes the flag is right in front of you. Look at the page title!",
            "flag": "flag{hidden_in_title}",
            "points": 5
        },
        {
            "title": "Steganography Image",
            "description": "There's a hidden message in the image 'cs.jpg' in the static folder. Use steganography tools to extract it!",
            "flag": "flag{stego_image_found}",
            "points": 35
        },
        {
            "title": "SQL Injection",
            "description": "Find the SQL injection vulnerability in the login form and bypass authentication!",
            "flag": "flag{sql_injection_success}",
            "points": 40
        },
        {
            "title": "XSS Attack",
            "description": "Can you trigger a JavaScript alert on the feedback page?",
            "flag": "flag{xss_alert_triggered}",
            "points": 25
        },
        {
            "title": "Obfuscated JS",
            "description": "The flag is hidden in an obfuscated JavaScript file in the static folder. Deobfuscate it!",
            "flag": "flag{js_deobfuscated}",
            "points": 30
        },
        {
            "title": "Logic Puzzle",
            "description": "What is the next number in the sequence: 2, 6, 12, 20, ? (flag format: flag{number})",
            "flag": "flag{30}",
            "points": 15
        },
        {
            "title": "Trivia: CTF History",
            "description": "In which year was the first DEF CON CTF held? (flag format: flag{year})",
            "flag": "flag{1996}",
            "points": 10
        },
        {
            "title": "Forensics: PCAP Analysis",
            "description": "Analyze the provided PCAP file and find the flag in the HTTP traffic.",
            "flag": "flag{pcap_http_flag}",
            "points": 35
        },
        {
            "title": "Password Cracking",
            "description": "Crack the following hash: 5f4dcc3b5aa765d61d8327deb882cf99 (flag format: flag{plaintext})",
            "flag": "flag{password}",
            "points": 20
        },
        {
            "title": "Regex Master",
            "description": "Find a string that matches the regex: ^flag\{[a-z]{8}\}$ (flag format: flag{abcdefgh})",
            "flag": "flag{abcdefgh}",
            "points": 15
        },
        {
            "title": "Network Trivia",
            "description": "What port does HTTPS use by default? (flag format: flag{port})",
            "flag": "flag{443}",
            "points": 10
        },
        {
            "title": "Encoding Chain",
            "description": "The flag is base64, then hex, then reversed. Can you decode it? '3d7b67616c6627' (flag format: flag{...})",
            "flag": "flag{lag7d3}",
            "points": 25
        },
        {
            "title": "Zip Bomb",
            "description": "Download and analyze the zip file in the static folder. The flag is in the deepest file!",
            "flag": "flag{zip_bombed}",
            "points": 30
        },
        {
            "title": "Classic Caesar",
            "description": "Decrypt this Caesar cipher (shift 13): synt{fghqrag_rapbqvat}",
            "flag": "flag{student_encoding}",
            "points": 20
        },
        {
            "title": "Trivia: RFC 1918",
            "description": "Name one of the private IPv4 address ranges (flag format: flag{range})",
            "flag": "flag{10.0.0.0/8}",
            "points": 10
        }
    ]
    print("🌱 Seeding challenges...")
    for challenge_data in challenges:
        add_challenge(**challenge_data)

    # Additional unique challenges to reach 50+
    extra_challenges = [
        {"title": "OSINT: Company Careers", "description": "Find the hidden flag in the careers page HTML comments of the provided mirror site.", "flag": "flag{careers_comment}", "points": 15},
        {"title": "Web Headers", "description": "Inspect response headers for the landing page. One header value contains the flag.", "flag": "flag{in_the_headers}", "points": 10},
        {"title": "Robots Exposed", "description": "The robots.txt references a disallowed path containing the flag.", "flag": "flag{bad_robots}", "points": 10},
        {"title": "Directory Bruteforce", "description": "Use a small wordlist to discover a hidden admin path and collect the flag displayed there.", "flag": "flag{found_hidden_dir}", "points": 25},
        {"title": "JWT 101", "description": "A JWT uses 'none' algorithm. Modify it to become admin and see the flag.", "flag": "flag{none_alg_bad}", "points": 40},
        {"title": "JWT Key Leak", "description": "The HS256 secret leaked in public JS. Sign a token and read the flag.", "flag": "flag{signed_by_me}", "points": 45},
        {"title": "SQL Boolean-Based", "description": "The product filter is vulnerable to boolean-based SQLi. Extract the flag column.", "flag": "flag{boolean_truth}", "points": 50},
        {"title": "SQL Time-Based", "description": "Use time delays to infer characters of the secret flag.", "flag": "flag{time_will_tell}", "points": 60},
        {"title": "Path Traversal", "description": "Read ../../flag.txt via an image download endpoint.", "flag": "flag{traversal_ok}", "points": 35},
        {"title": "LFI with PHP Wrappers", "description": "Use php://filter to read source and find the flag.", "flag": "flag{phar_filters}", "points": 55},
        {"title": "Command Injection", "description": "Ping form concatenates input. Inject a command to read the flag.", "flag": "flag{semicolon_surprise}", "points": 65},
        {"title": "XXE Basics", "description": "Abuse XML parser to read /etc/hostname and find embedded flag.", "flag": "flag{xxe_file_read}", "points": 45},
        {"title": "SSRF Metadata", "description": "Discover SSRF to fetch instance metadata where the flag resides.", "flag": "flag{169_254_win}", "points": 70},
        {"title": "Subdomain Takeover", "description": "A CNAME points to an unclaimed host. Claim it and serve the flag.", "flag": "flag{cnamed_you}", "points": 55},
        {"title": "Weak RSA", "description": "Given n and e with small d vulnerability (Wiener), recover private key and flag.", "flag": "flag{wiener_works}", "points": 80},
        {"title": "RSA Common Modulus", "description": "Two ciphertexts share modulus with different exponents. Recover the plaintext flag.", "flag": "flag{common_modulus}", "points": 85},
        {"title": "Vigenere", "description": "Break a repeating-key cipher and extract the flag.", "flag": "flag{vigenere_broken}", "points": 35},
        {"title": "Playfair", "description": "Decrypt a Playfair cipher text to reveal the flag.", "flag": "flag{playfair_ftw}", "points": 40},
        {"title": "Rail Fence", "description": "Unscramble a rail fence cipher (key=3).", "flag": "flag{zigzag_done}", "points": 20},
        {"title": "XOR Single-Byte", "description": "Single-byte XOR encrypted text; find the key and the flag.", "flag": "flag{x0r_single}", "points": 30},
        {"title": "XOR Repeating", "description": "Repeating-key XOR with English text; recover key and flag.", "flag": "flag{x0r_repeat}", "points": 50},
        {"title": "PNG LSB Stego", "description": "Extract LSBs from an image to reconstruct the flag.", "flag": "flag{lsb_recovered}", "points": 45},
        {"title": "WAV Spectrogram", "description": "Open the audio file spectrogram; the flag is visible.", "flag": "flag{see_the_sound}", "points": 30},
        {"title": "PCAP DNS Exfil", "description": "Reassemble DNS TXT exfiltration to read the flag.", "flag": "flag{dns_txt_data}", "points": 55},
        {"title": "PCAP HTTP Chunked", "description": "Decode chunked transfer and extract the flag from the body.", "flag": "flag{chunky_style}", "points": 35},
        {"title": "ELF Strings", "description": "Run strings on the binary; but the flag is XOR'd. Recover it.", "flag": "flag{not_plain_strings}", "points": 30},
        {"title": "ELF Patching", "description": "Patch a conditional jump to print the flag.", "flag": "flag{jmp2win}", "points": 65},
        {"title": "Python Bytecode", "description": "Decompile a .pyc and evaluate the computation to get the flag.", "flag": "flag{pyc_decompiled}", "points": 40},
        {"title": "Java Reversing", "description": "Decompile a .jar; constants hide the flag after simple math.", "flag": "flag{jad_win}", "points": 35},
        {"title": "Buffer Overflow 1", "description": "Smash the stack to reach the win() function.", "flag": "flag{ret2win}", "points": 75},
        {"title": "Format String", "description": "Leak memory with %p to find the flag in memory.", "flag": "flag{printf_leak}", "points": 70},
        {"title": "ROP Gadgets", "description": "Build a ROP chain to call system('/bin/cat flag.txt').", "flag": "flag{rop_ruler}", "points": 90},
        {"title": "Heap Use-After-Free", "description": "Exploit UAF to overwrite function pointer and print flag.", "flag": "flag{heap_artist}", "points": 95},
        {"title": "Zlib Inflate", "description": "Data is double-compressed. Inflate to reveal the flag.", "flag": "flag{inflate_twice}", "points": 20},
        {"title": "Base85", "description": "Decode Ascii85 text to retrieve the flag.", "flag": "flag{ascii85_ok}", "points": 15},
        {"title": "URL Encoding Chain", "description": "Multiple layers of URL encoding hide the flag.", "flag": "flag{percent_party}", "points": 20},
        {"title": "Hex + ROT", "description": "Hex-decode then apply ROT47 to see the flag.", "flag": "flag{rot_after_hex}", "points": 25},
        {"title": "Git Leak", "description": "An exposed .git reveals a previous commit with the flag.", "flag": "flag{git_digging}", "points": 55},
        {"title": "S3 Bucket", "description": "Public S3 bucket listing contains a text file with the flag.", "flag": "flag{s3_open_bucket}", "points": 45},
        {"title": "CORS Misconfig", "description": "Abuse wildcard CORS to read a sensitive flag endpoint.", "flag": "flag{corsy_business}", "points": 60},
        {"title": "HTTP Request Smuggling", "description": "Smuggle a request to the backend to fetch /flag.", "flag": "flag{smuggled_it}", "points": 85},
        {"title": "Padding Oracle", "description": "Exploit CBC padding oracle to decrypt the flag cookie.", "flag": "flag{cbc_padding_game}", "points": 95},
        {"title": "JWT Kid Confusion", "description": "kid header used for file path. Point to flag file.", "flag": "flag{kid_is_key}", "points": 80},
        {"title": "Zip Password", "description": "Zip is encrypted with weak password; crack and read flag.txt.", "flag": "flag{rockyou_works}", "points": 40},
        {"title": "PDF Hidden Layer", "description": "A hidden layer contains the flag; use qpdf or pdf-parser.", "flag": "flag{pdf_layers}", "points": 35},
        {"title": "Excel Macro", "description": "VBA macro obfuscation hides the flag. Deobfuscate.", "flag": "flag{vba_tricks}", "points": 50},
        {"title": "Android APK", "description": "Decompile an APK; resources string contains the flag.", "flag": "flag{apktool_time}", "points": 45},
        {"title": "iOS Plist", "description": "A plist contains Base64 data; decode to get the flag.", "flag": "flag{plist_found}", "points": 40},
        {"title": "Kerberoasting", "description": "Crack a captured service ticket to recover the flag.", "flag": "flag{tgs_cracked}", "points": 90},
        {"title": "Linux Forensics", "description": "Analyze bash history and crontab to find the flag.", "flag": "flag{cron_history}", "points": 35},
        {"title": "Windows Registry", "description": "A registry export hides the flag under Run keys.", "flag": "flag{reg_run_flag}", "points": 40},
        {"title": "Memory Dump", "description": "Strings + volatility to locate the flag in RAM.", "flag": "flag{mem_spelunk}", "points": 85},
        {"title": "Docker Misconfig", "description": "Sensitive file mounted into container; read /flag.", "flag": "flag{bind_mount_bad}", "points": 60},
        {"title": "Kubernetes Secret", "description": "A secret is base64-encoded in a YAML; decode to flag.", "flag": "flag{k8s_secrets_out}", "points": 70},
        {"title": "Cron Injection", "description": "Writable crontab allows command injection to print flag.", "flag": "flag{cron_pwn}", "points": 75},
        {"title": "Weak PRNG", "description": "Predict a linear congruential generator to recover the flag.", "flag": "flag{lcg_predictable}", "points": 80}
    ]

    for challenge_data in extra_challenges:
        add_challenge(**challenge_data)

    print(f"✅ Seeding complete. Total challenges in DB: {Challenge.query.count()}")

if __name__ == "__main__":
    with app.app_context():
        print("🚀 Starting database seeding...")
        
        # Create admin user
        create_admin_user()
        
        # Seed challenges
        seed_challenges()
        
        print("\n🎉 Database seeding completed!")
        print("You can now:")
        print("1. Login as admin (admin/admin123) to add more challenges")
        print("2. Create regular user accounts to solve challenges")
        print("3. View the scoreboard at /scoreboard") 