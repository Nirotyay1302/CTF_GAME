#!/usr/bin/env python3
"""
Create additional CTF challenges with comprehensive explanations
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db
from models import Challenge, Hint
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib

def create_additional_challenges():
    """Create additional CTF challenges with detailed explanations"""
    print("🧩 Creating additional comprehensive CTF challenges...")
    
    with app.app_context():
        try:
            # Get encryption key from app config
            ENCRYPTION_KEY = app.config.get('ENCRYPTION_KEY', Fernet.generate_key())
            cipher_suite = Fernet(ENCRYPTION_KEY)
            
            challenges_data = [
                # FORENSICS CHALLENGES
                {
                    'title': 'Metadata Analysis',
                    'description': 'Download the image file and analyze its metadata. The flag is hidden in one of the EXIF fields.',
                    'category': 'Forensics',
                    'difficulty': 'medium',
                    'points': 150,
                    'flag': 'CTF{metadata_reveals_secrets}',
                    'answer_explanation': '''
# Metadata Analysis Solution

## What You Learned
This challenge teaches you about metadata in files, particularly EXIF data in images. Metadata is "data about data" - information embedded in files that describes various properties.

## Why This Matters
Forensic investigators often examine metadata to:
- Determine when a file was created or modified
- Identify the device that created the file
- Find location data (GPS coordinates)
- Discover hidden information

## Real-World Applications
- Digital forensics investigations
- Privacy concerns (accidentally leaking location data)
- Verifying authenticity of photos
- Intelligence gathering

## Technical Explanation
EXIF (Exchangeable Image File Format) data can contain:
- Camera make and model
- Date and time the photo was taken
- Camera settings (aperture, shutter speed, etc.)
- GPS coordinates
- Comments and other custom fields

Tools like ExifTool, metadata viewers, and even some image editors can reveal this information.
''',
                    'solution_steps': '''
1. Download the image file
2. Use an EXIF viewer tool (like ExifTool, online EXIF viewers, or built-in OS tools)
3. Examine all metadata fields, particularly looking at:
   - Comments
   - Author/Artist field
   - Description
   - Copyright
4. Find the flag in the "Artist" field
''',
                    'hints': [
                        {'content': 'EXIF data contains information about when and how an image was created', 'cost': 10},
                        {'content': 'Try using an online EXIF viewer or ExifTool', 'cost': 15},
                        {'content': 'Check all metadata fields, especially the Author/Artist field', 'cost': 25}
                    ]
                },
                {
                    'title': 'Network Packet Analysis',
                    'description': 'Analyze the provided PCAP file to find the flag that was transmitted over the network.',
                    'category': 'Forensics',
                    'difficulty': 'hard',
                    'points': 250,
                    'flag': 'CTF{packet_capture_analysis}',
                    'answer_explanation': '''
# Network Packet Analysis Solution

## What You Learned
This challenge introduces you to network packet analysis, a critical skill in cybersecurity for understanding network traffic and identifying suspicious activities.

## Why This Matters
Packet analysis is essential for:
- Network troubleshooting
- Security incident investigation
- Malware analysis
- Network forensics

## Real-World Applications
- Detecting data exfiltration
- Identifying command and control (C2) traffic
- Analyzing network-based attacks
- Monitoring network performance

## Technical Explanation
PCAP (Packet Capture) files contain recorded network traffic. Wireshark and similar tools allow you to:

1. Filter traffic by protocol (HTTP, DNS, TCP, etc.)
2. Follow TCP streams to reconstruct sessions
3. Analyze packet headers and payloads
4. Extract files transferred over the network

In this challenge, the flag was transmitted in an unencrypted HTTP request, demonstrating why encryption is crucial for sensitive data.
''',
                    'solution_steps': '''
1. Open the PCAP file with Wireshark or another packet analysis tool
2. Look for HTTP traffic (filter: http)
3. Examine GET and POST requests for suspicious parameters
4. Follow TCP streams to see complete conversations
5. Find an HTTP POST request containing the flag in the form data
''',
                    'hints': [
                        {'content': 'Use Wireshark to open and analyze the PCAP file', 'cost': 20},
                        {'content': 'Focus on HTTP traffic - try using the filter "http"', 'cost': 30},
                        {'content': 'Look for POST requests and examine their content', 'cost': 40}
                    ]
                },
                
                # REVERSE ENGINEERING CHALLENGES
                {
                    'title': 'Simple Binary Analysis',
                    'description': 'Download and analyze the provided binary file. Find the hidden flag by examining the strings or disassembling the code.',
                    'category': 'Reverse',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{static_analysis_basics}',
                    'answer_explanation': '''
# Simple Binary Analysis Solution

## What You Learned
This challenge introduces basic reverse engineering concepts, focusing on static analysis techniques to examine compiled programs without running them.

## Why This Matters
Reverse engineering skills are valuable for:
- Malware analysis
- Vulnerability research
- Software interoperability
- Legacy code understanding

## Real-World Applications
- Security researchers analyzing malicious software
- Software developers understanding undocumented code
- Digital forensics investigations
- Competitive analysis of proprietary software

## Technical Explanation
Static analysis examines a program without execution. Key techniques include:

1. **String extraction**: Finding human-readable text in binary files
2. **Disassembly**: Converting machine code to assembly language
3. **Control flow analysis**: Understanding program execution paths
4. **Symbol analysis**: Identifying functions and variables

Tools like strings, objdump, IDA Pro, Ghidra, and Radare2 help with these tasks.
''',
                    'solution_steps': '''
1. Download the binary file
2. Run the "strings" command to extract readable text: `strings binary_file`
3. Look for text that matches the CTF flag format
4. If not found with strings, use a disassembler like Ghidra or IDA Free
5. Look for string comparisons or flag validation functions
''',
                    'hints': [
                        {'content': 'Try using the "strings" command on the binary', 'cost': 15},
                        {'content': 'Look for text that matches the CTF{...} pattern', 'cost': 25},
                        {'content': 'If strings doesn\'t work, try a disassembler like Ghidra', 'cost': 35}
                    ]
                },
                {
                    'title': 'Logic Puzzle',
                    'description': 'This program checks if your input is the correct flag. Reverse engineer the validation logic to determine what input will be accepted.',
                    'category': 'Reverse',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{reverse_the_logic}',
                    'answer_explanation': '''
# Logic Puzzle Solution

## What You Learned
This challenge teaches you how to reverse engineer program logic to understand how input validation works, allowing you to determine what input will pass the checks.

## Why This Matters
Understanding validation logic is crucial for:
- Finding security vulnerabilities
- Bypassing protection mechanisms
- Understanding complex algorithms
- Debugging software issues

## Real-World Applications
- Vulnerability researchers finding authentication bypasses
- Security professionals testing input validation
- Software developers debugging validation issues
- Malware analysts understanding evasion techniques

## Technical Explanation
The program implements a custom validation algorithm that:

1. Takes user input and performs a series of transformations
2. Compares the result against hardcoded values
3. Only accepts input that produces the expected result

By analyzing the assembly code or decompiled source, you can work backward from the expected output to determine what input would produce it.
''',
                    'solution_steps': '''
1. Use a disassembler like Ghidra or IDA Pro to analyze the binary
2. Locate the input validation function
3. Analyze the logic to understand how input is transformed
4. Identify the comparison values (what the program expects)
5. Work backward to determine what input would produce those values
6. Alternatively, patch the binary to reveal the expected input
''',
                    'hints': [
                        {'content': 'Look for functions that process your input character by character', 'cost': 30},
                        {'content': 'Find comparison operations that check the processed input', 'cost': 40},
                        {'content': 'Try to reverse the mathematical operations being performed', 'cost': 50}
                    ]
                },
                
                # PWNING/BINARY EXPLOITATION CHALLENGES
                {
                    'title': 'Buffer Overflow Basics',
                    'description': 'This program has a buffer overflow vulnerability. Exploit it to gain control of the execution flow and get the flag.',
                    'category': 'Pwn',
                    'difficulty': 'medium',
                    'points': 250,
                    'flag': 'CTF{buffer_overflow_101}',
                    'answer_explanation': '''
# Buffer Overflow Basics Solution

## What You Learned
This challenge introduces buffer overflow vulnerabilities, one of the most common memory corruption issues in software written in languages like C and C++.

## Why This Matters
Buffer overflows are critical to understand because:
- They remain common in real-world software
- They can lead to arbitrary code execution
- They bypass memory protection mechanisms
- They're the foundation for many advanced exploits

## Real-World Applications
- Vulnerability researchers finding exploitable bugs
- Security professionals conducting penetration tests
- Software developers writing secure code
- CTF competitions and security training

## Technical Explanation
A buffer overflow occurs when a program writes data beyond the allocated buffer boundaries. This happens because languages like C don't automatically check array bounds.

Key concepts:
1. **Stack layout**: Understanding how local variables, return addresses, and parameters are stored
2. **Return address overwrite**: Changing where the function returns to
3. **Shellcode**: Injecting executable code into memory
4. **Memory protections**: Techniques like ASLR, DEP, and stack canaries that complicate exploitation
''',
                    'solution_steps': '''
1. Analyze the program to find the vulnerable function (likely using gets, strcpy, etc.)
2. Determine the buffer size and offset to the return address
3. Create a pattern of characters to identify the exact offset
4. Craft an input that overwrites the return address with the address of a function that prints the flag
5. Submit the exploit string to get the flag
''',
                    'hints': [
                        {'content': 'Look for unsafe functions like gets(), strcpy(), or sprintf()', 'cost': 25},
                        {'content': 'Try sending a large input to see if you can crash the program', 'cost': 35},
                        {'content': 'Use a pattern generator to find the exact offset to the return address', 'cost': 45}
                    ]
                },
                
                # OSINT CHALLENGES
                {
                    'title': 'Digital Footprint',
                    'description': 'Find information about the fictional person "Alex Morgan" who works at TechCorp and has recently posted about a CTF event. The flag is hidden in one of their social media profiles.',
                    'category': 'OSINT',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{osint_digital_investigation}',
                    'answer_explanation': '''
# Digital Footprint Solution

## What You Learned
This challenge teaches Open Source Intelligence (OSINT) techniques for gathering information about individuals from publicly available sources.

## Why This Matters
OSINT skills are valuable for:
- Security professionals conducting reconnaissance
- Investigators gathering information
- Privacy-conscious individuals understanding their exposure
- Organizations assessing their public information leakage

## Real-World Applications
- Security assessments and penetration testing
- Human resources vetting candidates
- Law enforcement investigations
- Competitive intelligence gathering

## Technical Explanation
OSINT involves collecting and analyzing information from public sources such as:

1. **Social media profiles**: Facebook, Twitter, LinkedIn, Instagram, etc.
2. **Professional websites**: Company directories, professional organizations
3. **Public records**: Government databases, court records
4. **Data aggregators**: People search engines, archived content

By correlating information across multiple sources, investigators can build comprehensive profiles of individuals or organizations.
''',
                    'solution_steps': '''
1. Search for "Alex Morgan TechCorp" on various search engines
2. Check common social media platforms (LinkedIn, Twitter, GitHub, etc.)
3. Look for mentions of CTF events in recent posts
4. Examine profile information, including bios, about sections, and pinned posts
5. Find the GitHub profile where the flag is hidden in the bio
''',
                    'hints': [
                        {'content': 'Start with professional networks like LinkedIn', 'cost': 20},
                        {'content': 'Check developer platforms like GitHub', 'cost': 30},
                        {'content': 'Look at the bio or about sections of profiles', 'cost': 40}
                    ]
                },
                
                # MOBILE SECURITY CHALLENGES
                {
                    'title': 'Android APK Analysis',
                    'description': 'Download and analyze the provided Android APK file. The flag is hidden within the application code.',
                    'category': 'Mobile',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{decompiled_apk_secrets}',
                    'answer_explanation': '''
# Android APK Analysis Solution

## What You Learned
This challenge introduces mobile application security analysis, focusing on Android APK files and how to extract information from them.

## Why This Matters
Mobile app analysis skills are important because:
- Mobile apps often contain sensitive data and logic
- They may have unique vulnerabilities compared to web apps
- Understanding their structure helps identify security issues
- Reverse engineering helps assess security claims

## Real-World Applications
- Security researchers analyzing malicious apps
- Penetration testers assessing mobile applications
- Developers understanding competitor implementations
- Compliance verification for security requirements

## Technical Explanation
Android APK files are essentially ZIP archives containing:

1. **DEX files**: Compiled Java/Kotlin code in Dalvik Executable format
2. **Resources**: Images, layouts, strings, and other assets
3. **AndroidManifest.xml**: App configuration and permissions
4. **Native libraries**: Compiled C/C++ code (.so files)

Tools like jadx, apktool, and dex2jar help decompile and analyze these components.
''',
                    'solution_steps': '''
1. Download the APK file
2. Use a tool like jadx-gui to decompile the APK
3. Explore the source code, focusing on:
   - Hardcoded strings
   - Authentication logic
   - Network communication
   - Data storage
4. Find the flag in a string resource or hardcoded in the MainActivity
''',
                    'hints': [
                        {'content': 'Use jadx-gui or apktool to decompile the APK', 'cost': 30},
                        {'content': 'Check the strings.xml resource file', 'cost': 40},
                        {'content': 'Look at the MainActivity class for hardcoded values', 'cost': 50}
                    ]
                },
                {
                    'title': 'iOS Secure Storage',
                    'description': 'Analyze the iOS application and find where the flag is stored in the secure storage.',
                    'category': 'Mobile',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{keychain_secrets_exposed}',
                    'answer_explanation': '''
# iOS Secure Storage Solution

## What You Learned
This challenge teaches you about iOS secure storage mechanisms and how to analyze iOS applications for sensitive data storage.

## Why This Matters
Understanding iOS secure storage is important because:
- iOS apps often store sensitive user data
- Proper use of the Keychain is critical for security
- Insecure storage can lead to data breaches
- Many real-world apps misuse secure storage APIs

## Real-World Applications
- Mobile app security assessments
- iOS penetration testing
- Secure app development
- Compliance with data protection regulations

## Technical Explanation
iOS provides several mechanisms for secure data storage:

1. **Keychain**: The most secure option, protected by the Secure Enclave
2. **Data Protection API**: File encryption with different protection classes
3. **Secure Enclave**: Hardware-based key manager
4. **App sandbox**: Isolation between applications

Tools like Frida, Objection, and a jailbroken device can help analyze these security mechanisms.
''',
                    'solution_steps': '''
1. Use a jailbroken iOS device or simulator
2. Install and run the application
3. Use Frida or Objection to hook into the application
4. Monitor Keychain access operations
5. Extract the flag from the Keychain entry labeled "secret_flag"
''',
                    'hints': [
                        {'content': 'You need to examine the iOS Keychain storage', 'cost': 30},
                        {'content': 'Try using Frida or Objection to hook into Keychain APIs', 'cost': 40},
                        {'content': 'Look for a Keychain entry with the label "secret_flag"', 'cost': 50}
                    ]
                },
                
                # WEB SECURITY CHALLENGES
                {
                    'title': 'SQL Injection Advanced',
                    'description': 'This web application has a SQL injection vulnerability in its login form. Bypass authentication and find the flag in the admin panel.',
                    'category': 'Web',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{sql_injection_master}',
                    'answer_explanation': '''
# SQL Injection Advanced Solution

## What You Learned
This challenge teaches advanced SQL injection techniques to bypass authentication and access restricted areas of a web application.

## Why This Matters
SQL injection remains one of the most critical web vulnerabilities because:
- It can lead to unauthorized data access
- It may allow authentication bypass
- It can enable data modification or deletion
- It's still common despite being well-known

## Real-World Applications
- Web application security testing
- Secure coding practices
- Database security hardening
- Input validation implementation

## Technical Explanation
SQL injection occurs when user input is incorrectly handled and incorporated into SQL queries. In this challenge:

1. The login form takes username and password inputs
2. These inputs are directly concatenated into a SQL query
3. By injecting SQL syntax, you can alter the query's logic
4. This allows bypassing the authentication check

Prevention techniques include prepared statements, parameterized queries, and input validation.
''',
                    'solution_steps': '''
1. Access the login form
2. Try basic SQL injection in the username field: `admin' --`
3. If that doesn't work, try more advanced payloads: `admin' OR '1'='1' --`
4. Once logged in as admin, navigate to the admin panel
5. Find the flag displayed on the admin dashboard
''',
                    'hints': [
                        {'content': 'Try using comment syntax (-- or #) to ignore the rest of the query', 'cost': 25},
                        {'content': 'The OR operator can help you create always-true conditions', 'cost': 35},
                        {'content': 'Focus on the username field, which is more likely vulnerable', 'cost': 45}
                    ]
                },
                {
                    'title': 'JWT Token Manipulation',
                    'description': 'The web application uses JWT for authentication. Find and exploit a vulnerability in the JWT implementation to gain admin access.',
                    'category': 'Web',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{jwt_algorithm_confusion}',
                    'answer_explanation': '''
# JWT Token Manipulation Solution

## What You Learned
This challenge teaches you about JSON Web Tokens (JWT), their structure, and common security vulnerabilities in JWT implementations.

## Why This Matters
JWT security is critical because:
- JWTs are widely used for authentication and authorization
- Vulnerable implementations can lead to account takeover
- Many developers don't understand JWT security nuances
- Algorithm confusion attacks are common but preventable

## Real-World Applications
- API security testing
- Authentication system design
- Token-based authorization systems
- Single sign-on implementations

## Technical Explanation
JWT consists of three parts: header, payload, and signature, each base64-encoded and separated by dots.

The vulnerability in this challenge is an algorithm confusion attack:
1. The server accepts tokens signed with the RS256 algorithm (asymmetric)
2. But it also accepts tokens signed with HS256 (symmetric)
3. When using HS256, the public key is used as the secret key
4. This allows forging valid tokens if you know the public key

Prevention requires explicitly checking the algorithm and rejecting unexpected ones.
''',
                    'solution_steps': '''
1. Obtain a valid JWT token by logging in as a regular user
2. Decode the token to examine its structure (header, payload, signature)
3. Find the public key used for verification (often available in the /jwks endpoint)
4. Change the payload to include {"role": "admin"}
5. Change the algorithm in the header from RS256 to HS256
6. Sign the token using the public key as the secret
7. Replace your original token with the forged one
8. Access the admin area to find the flag
''',
                    'hints': [
                        {'content': 'Look for the algorithm field ("alg") in the JWT header', 'cost': 30},
                        {'content': 'Try changing the algorithm from RS256 to HS256', 'cost': 40},
                        {'content': 'You\'ll need to find the public key to sign your forged token', 'cost': 50}
                    ]
                },
                
                # CRYPTOGRAPHY CHALLENGES
                {
                    'title': 'RSA Basics',
                    'description': 'You\'ve intercepted an RSA encrypted message along with the public key parameters. Decrypt the message to find the flag.',
                    'category': 'Crypto',
                    'difficulty': 'medium',
                    'points': 250,
                    'flag': 'CTF{rsa_mathematics_fundamentals}',
                    'answer_explanation': '''
# RSA Basics Solution

## What You Learned
This challenge introduces the RSA cryptosystem, one of the most widely used public-key cryptography algorithms, and teaches you its mathematical foundations.

## Why This Matters
Understanding RSA is important because:
- It's fundamental to modern secure communications
- It's used in HTTPS, SSH, and many other protocols
- Its security relies on the difficulty of factoring large numbers
- Implementations can have vulnerabilities despite mathematical soundness

## Real-World Applications
- Secure communication protocols
- Digital signatures
- Certificate authorities
- Secure key exchange

## Technical Explanation
RSA encryption works as follows:

1. **Key Generation**:
   - Choose two large prime numbers p and q
   - Calculate n = p × q
   - Calculate φ(n) = (p-1) × (q-1)
   - Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
   - Calculate d such that (d × e) mod φ(n) = 1
   - Public key: (n, e), Private key: (n, d)

2. **Encryption**: c = m^e mod n

3. **Decryption**: m = c^d mod n

In this challenge, the values of p and q were small enough to factor n, allowing you to calculate the private key.
''',
                    'solution_steps': '''
1. Extract the public key parameters (n, e) from the provided file
2. Factor n into its prime components p and q (possible because they're small)
3. Calculate φ(n) = (p-1) × (q-1)
4. Calculate the private key d = e^(-1) mod φ(n)
5. Decrypt the ciphertext using m = c^d mod n
6. Convert the resulting number to ASCII to get the flag
''',
                    'hints': [
                        {'content': 'You need to factor n into its prime components p and q', 'cost': 25},
                        {'content': 'Use the extended Euclidean algorithm to find the modular inverse', 'cost': 35},
                        {'content': 'Online tools like factordb.com can help with factoring', 'cost': 45}
                    ]
                },
                {
                    'title': 'Hash Length Extension',
                    'description': 'The web application uses a vulnerable authentication mechanism based on hash signatures. Exploit the length extension vulnerability to forge an admin request.',
                    'category': 'Crypto',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{hash_length_extension_attack}',
                    'answer_explanation': '''
# Hash Length Extension Solution

## What You Learned
This challenge teaches you about hash length extension attacks, which exploit vulnerabilities in how some hash functions (like SHA-1 and SHA-256) can be manipulated.

## Why This Matters
Hash length extension attacks are important to understand because:
- Many systems use hash-based signatures for authentication
- Vulnerable implementations are still common
- The attack can lead to request forgery and authentication bypass
- It demonstrates why HMAC is preferred over simple hash concatenation

## Real-World Applications
- Web application security testing
- API authentication design
- Secure token implementation
- Message authentication systems

## Technical Explanation
The vulnerability occurs when a system creates a signature like:

`signature = hash(secret + message)`

And then sends `message` and `signature` to verify authenticity.

The problem is that with hash functions like SHA-1 and SHA-256 that use the Merkle-Damgård construction, if you know:
- `hash(secret + message)` (the signature)
- The length of `secret + message`
- `message`

You can calculate `hash(secret + message + padding + additional_data)` without knowing the secret.

This allows attackers to append data to the original message while producing a valid signature.
''',
                    'solution_steps': '''
1. Analyze the authentication mechanism to confirm it uses `hash(secret + data)` for signatures
2. Obtain a valid signature for a known message
3. Estimate the length of the secret key
4. Use a hash length extension tool (like hash_extender)
5. Craft a new message that appends "&admin=true" to the original data
6. Calculate the new signature using the length extension attack
7. Submit the extended message with the forged signature
8. Access the admin functionality to find the flag
''',
                    'hints': [
                        {'content': 'Look at how the application validates signatures', 'cost': 30},
                        {'content': 'Try using the hash_extender tool', 'cost': 40},
                        {'content': 'You\'ll need to guess the secret length - try common values like 16, 32, or 64 bytes', 'cost': 50}
                    ]
                }
            ]
            
            # Add challenges to database
            for challenge_data in challenges_data:
                # Encrypt the flag
                flag_bytes = challenge_data['flag'].encode('utf-8')
                encrypted_flag = cipher_suite.encrypt(flag_bytes)
                
                # Create a salted hash for flag validation
                salt = os.urandom(16)
                flag_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    flag_bytes, 
                    salt, 
                    100000  # Number of iterations
                )
                
                # Create the challenge
                challenge = Challenge(
                    title=challenge_data['title'],
                    description=challenge_data['description'],
                    flag_encrypted=encrypted_flag,
                    points=challenge_data['points'],
                    category=challenge_data['category'],
                    difficulty=challenge_data['difficulty'],
                    flag_salt=salt,
                    flag_hash=flag_hash,
                    answer_explanation=challenge_data['answer_explanation'],
                    solution_steps=challenge_data['solution_steps']
                )
                
                db.session.add(challenge)
                db.session.flush()  # Get the challenge ID
                
                # Add hints
                for i, hint_data in enumerate(challenge_data['hints']):
                    hint = Hint(
                        challenge_id=challenge.id,
                        content=hint_data['content'],
                        cost=hint_data['cost'],
                        display_order=i
                    )
                    db.session.add(hint)
            
            db.session.commit()
            print(f"✅ Added {len(challenges_data)} new challenges with detailed explanations!")
            
        except Exception as e:
            print(f"❌ Error creating challenges: {e}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    create_additional_challenges()
    print("🎉 Additional challenges created successfully!")