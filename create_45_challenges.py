#!/usr/bin/env python3
"""
Create 45 comprehensive CTF challenges with hints and explanations
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db
from models import Challenge, Hint
from datetime import datetime

def create_comprehensive_challenges():
    """Create 45 diverse CTF challenges across multiple categories"""
    print("🧩 Creating 45 comprehensive CTF challenges...")
    
    with app.app_context():
        try:
            # Clear existing challenges
            print("🗑️ Clearing existing challenges...")
            Challenge.query.delete()
            Hint.query.delete()
            
            challenges_data = [
                # WEB CHALLENGES (15)
                {
                    'title': 'Basic HTML Inspection',
                    'description': 'The flag is hidden in the HTML source code of this page. View the source to find it.',
                    'category': 'web',
                    'difficulty': 'easy',
                    'points': 50,
                    'flag': 'CTF{view_source_is_basic}',
                    'answer_explanation': 'This challenge teaches the fundamental skill of viewing HTML source code. The flag was hidden in an HTML comment.',
                    'solution_steps': '1. Right-click on the page\n2. Select "View Page Source"\n3. Look for HTML comments containing the flag\n4. Submit the flag',
                    'hints': [
                        {'content': 'Try right-clicking on the page and looking for "View Source"', 'cost': 5},
                        {'content': 'Look for HTML comments <!-- like this -->', 'cost': 10}
                    ]
                },
                {
                    'title': 'Cookie Monster',
                    'description': 'I left something important in the cookies. Can you find it?',
                    'category': 'web',
                    'difficulty': 'easy',
                    'points': 75,
                    'flag': 'CTF{cookies_are_tasty}',
                    'answer_explanation': 'This challenge demonstrates how sensitive information can be stored in browser cookies.',
                    'solution_steps': '1. Open browser developer tools (F12)\n2. Go to Application/Storage tab\n3. Look at Cookies for this domain\n4. Find the flag in one of the cookie values',
                    'hints': [
                        {'content': 'Check your browser\'s developer tools', 'cost': 5},
                        {'content': 'Look in the Application or Storage tab for cookies', 'cost': 10}
                    ]
                },
                {
                    'title': 'Hidden Form Fields',
                    'description': 'This form has some hidden fields. Maybe one of them contains something interesting?',
                    'category': 'web',
                    'difficulty': 'easy',
                    'points': 100,
                    'flag': 'CTF{hidden_fields_exposed}',
                    'answer_explanation': 'Hidden form fields are often used to store data that shouldn\'t be modified by users, but they\'re still visible in the HTML source.',
                    'solution_steps': '1. Inspect the form element\n2. Look for input fields with type="hidden"\n3. Check the value attributes of hidden fields\n4. Find the flag in one of the values',
                    'hints': [
                        {'content': 'Inspect the form element in the HTML', 'cost': 5},
                        {'content': 'Look for input tags with type="hidden"', 'cost': 10}
                    ]
                },
                {
                    'title': 'JavaScript Secrets',
                    'description': 'The flag is hidden somewhere in the JavaScript code. Can you find it?',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 150,
                    'flag': 'CTF{javascript_is_not_secure}',
                    'answer_explanation': 'Client-side JavaScript is never secure for hiding sensitive information as it\'s always visible to users.',
                    'solution_steps': '1. View page source\n2. Look through JavaScript code\n3. Check for obfuscated or encoded strings\n4. Decode any suspicious strings to find the flag',
                    'hints': [
                        {'content': 'Check the JavaScript files linked to this page', 'cost': 10},
                        {'content': 'Look for base64 encoded strings in the JS code', 'cost': 15}
                    ]
                },
                {
                    'title': 'SQL Injection Login',
                    'description': 'Can you bypass this login form? Username: admin',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{sql_injection_master}',
                    'answer_explanation': 'SQL injection occurs when user input is not properly sanitized before being used in SQL queries.',
                    'solution_steps': '1. Try common SQL injection payloads in the password field\n2. Use: \' OR \'1\'=\'1\' --\n3. This makes the SQL query always return true\n4. Successfully bypass the login to get the flag',
                    'hints': [
                        {'content': 'Try entering a single quote in the password field', 'cost': 15},
                        {'content': 'Use the classic payload: \' OR \'1\'=\'1\' --', 'cost': 25}
                    ]
                },
                {
                    'title': 'Directory Traversal',
                    'description': 'This file viewer seems to have some security issues. Can you read files you shouldn\'t?',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 250,
                    'flag': 'CTF{directory_traversal_success}',
                    'answer_explanation': 'Directory traversal attacks exploit insufficient security validation of user-supplied input file names.',
                    'solution_steps': '1. Try using ../ to go up directories\n2. Use ../../../../etc/passwd to try to read system files\n3. Look for the flag file in the root directory\n4. Use ../../../../flag.txt',
                    'hints': [
                        {'content': 'Try using ../ to navigate up directories', 'cost': 20},
                        {'content': 'Look for a flag.txt file in the root directory', 'cost': 30}
                    ]
                },
                {
                    'title': 'XSS Reflected',
                    'description': 'This search form reflects your input. Can you make it execute JavaScript?',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{xss_alert_success}',
                    'answer_explanation': 'Reflected XSS occurs when user input is immediately returned by a web application without proper validation.',
                    'solution_steps': '1. Try entering <script>alert(1)</script> in the search box\n2. If that doesn\'t work, try variations like <img src=x onerror=alert(1)>\n3. Successfully execute JavaScript to get the flag',
                    'hints': [
                        {'content': 'Try entering HTML tags in the search box', 'cost': 15},
                        {'content': 'Use <script>alert(1)</script> or similar payloads', 'cost': 25}
                    ]
                },
                {
                    'title': 'Command Injection',
                    'description': 'This ping tool executes system commands. Can you inject your own commands?',
                    'category': 'web',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{command_injection_pwned}',
                    'answer_explanation': 'Command injection occurs when user input is passed to system commands without proper sanitization.',
                    'solution_steps': '1. Try using command separators like ; or &&\n2. Use: 127.0.0.1; cat flag.txt\n3. Or try: 127.0.0.1 && ls -la\n4. Find and read the flag file',
                    'hints': [
                        {'content': 'Try using semicolons or && to chain commands', 'cost': 25},
                        {'content': 'Look for a flag.txt file using ls or cat commands', 'cost': 35}
                    ]
                },

                # CRYPTO CHALLENGES (10)
                {
                    'title': 'Caesar Cipher',
                    'description': 'Decode this message: PGS{pnrfne_pvcure_vf_rnfl}',
                    'category': 'crypto',
                    'difficulty': 'easy',
                    'points': 75,
                    'flag': 'CTF{caesar_cipher_is_easy}',
                    'answer_explanation': 'Caesar cipher shifts each letter by a fixed number. This used ROT13 (shift of 13).',
                    'solution_steps': '1. Recognize this as a Caesar cipher\n2. Try different shift values\n3. ROT13 (shift 13) reveals the flag\n4. Use online ROT13 decoder or manual shifting',
                    'hints': [
                        {'content': 'This looks like a Caesar cipher with letter substitution', 'cost': 5},
                        {'content': 'Try ROT13 - a shift of 13 positions', 'cost': 10}
                    ]
                },
                {
                    'title': 'Base64 Encoding',
                    'description': 'Decode this: Q1RGe2Jhc2U2NF9pc19ub3Rfc2VjdXJlfQ==',
                    'category': 'crypto',
                    'difficulty': 'easy',
                    'points': 50,
                    'flag': 'CTF{base64_is_not_secure}',
                    'answer_explanation': 'Base64 is an encoding scheme, not encryption. It\'s easily reversible.',
                    'solution_steps': '1. Recognize the == padding as Base64\n2. Use any Base64 decoder\n3. Decode to get the flag',
                    'hints': [
                        {'content': 'The == at the end suggests Base64 encoding', 'cost': 5},
                        {'content': 'Use an online Base64 decoder', 'cost': 10}
                    ]
                },
                {
                    'title': 'Hexadecimal Decoding',
                    'description': 'Convert this hex: 4354467b6865785f69735f6e756d626572735f616e645f6c6574746572737d',
                    'category': 'crypto',
                    'difficulty': 'easy',
                    'points': 75,
                    'flag': 'CTF{hex_is_numbers_and_letters}',
                    'answer_explanation': 'Hexadecimal uses base-16 numbering system with digits 0-9 and letters A-F.',
                    'solution_steps': '1. Recognize this as hexadecimal (only 0-9 and a-f)\n2. Convert hex to ASCII\n3. Each pair of hex digits represents one ASCII character',
                    'hints': [
                        {'content': 'This string only contains 0-9 and a-f - that\'s hexadecimal', 'cost': 5},
                        {'content': 'Convert hex to ASCII text', 'cost': 10}
                    ]
                },
                {
                    'title': 'Binary Message',
                    'description': 'Decode: 01000011010101000100011001111011011000100110100101101110011000010111001001111001010111110110100101110011010111110110011001110101011011100111101101',
                    'category': 'crypto',
                    'difficulty': 'medium',
                    'points': 100,
                    'flag': 'CTF{binary_is_fun}',
                    'answer_explanation': 'Binary uses only 0s and 1s. Each group of 8 bits represents one ASCII character.',
                    'solution_steps': '1. Split the binary into groups of 8 bits\n2. Convert each 8-bit group to decimal\n3. Convert decimal to ASCII character\n4. Combine all characters to get the flag',
                    'hints': [
                        {'content': 'Split this into groups of 8 bits (bytes)', 'cost': 10},
                        {'content': 'Convert each byte from binary to ASCII', 'cost': 15}
                    ]
                },
                {
                    'title': 'Morse Code',
                    'description': 'Decode: -.-. - ..-. { -- --- .-. ... . / .. ... / -.. --- - ... / .- -. -.. / -.. .- ... .... . ... }',
                    'category': 'crypto',
                    'difficulty': 'medium',
                    'points': 125,
                    'flag': 'CTF{morse_is_dots_and_dashes}',
                    'answer_explanation': 'Morse code represents letters and numbers using dots and dashes.',
                    'solution_steps': '1. Recognize dots and dashes as Morse code\n2. Use a Morse code chart or decoder\n3. Translate each sequence to letters\n4. Combine to form the flag',
                    'hints': [
                        {'content': 'Dots and dashes suggest Morse code', 'cost': 10},
                        {'content': 'Use a Morse code translation chart', 'cost': 15}
                    ]
                },

                # FORENSICS CHALLENGES (8)
                {
                    'title': 'Hidden in Plain Sight',
                    'description': 'This image looks normal, but something is hidden inside. Can you find it?',
                    'category': 'forensics',
                    'difficulty': 'easy',
                    'points': 100,
                    'flag': 'CTF{steganography_basics}',
                    'answer_explanation': 'Steganography hides data within other files. Images are common carriers.',
                    'solution_steps': '1. Use steganography tools like steghide or binwalk\n2. Try: strings image.jpg | grep CTF\n3. Check EXIF data with exiftool\n4. Look for hidden text in image metadata',
                    'hints': [
                        {'content': 'Try using the strings command on the image', 'cost': 10},
                        {'content': 'Check the image metadata or EXIF data', 'cost': 15}
                    ]
                },
                {
                    'title': 'Memory Dump Analysis',
                    'description': 'Analyze this memory dump to find the hidden flag.',
                    'category': 'forensics',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{memory_forensics_expert}',
                    'answer_explanation': 'Memory forensics involves analyzing RAM dumps to extract information.',
                    'solution_steps': '1. Use Volatility framework for memory analysis\n2. Try: volatility -f dump.mem imageinfo\n3. Extract processes: volatility -f dump.mem pslist\n4. Look for suspicious processes or strings',
                    'hints': [
                        {'content': 'Use Volatility framework for memory analysis', 'cost': 30},
                        {'content': 'Look for strings or processes containing the flag', 'cost': 40}
                    ]
                },

                # REVERSE ENGINEERING CHALLENGES (7)
                {
                    'title': 'Simple Binary Analysis',
                    'description': 'This binary contains a flag. Can you reverse engineer it?',
                    'category': 'reverse',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{reverse_engineering_fun}',
                    'answer_explanation': 'Static analysis of binaries can reveal hardcoded strings and logic.',
                    'solution_steps': '1. Use strings command: strings binary | grep CTF\n2. Use objdump for disassembly\n3. Look for hardcoded flag strings\n4. Analyze the main function logic',
                    'hints': [
                        {'content': 'Try the strings command on the binary', 'cost': 15},
                        {'content': 'Use objdump or ghidra for disassembly', 'cost': 25}
                    ]
                },
                {
                    'title': 'Password Checker',
                    'description': 'This program checks passwords. Find the correct password to get the flag.',
                    'category': 'reverse',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{password_cracked_successfully}',
                    'answer_explanation': 'Password checking logic can be analyzed to determine the correct password.',
                    'solution_steps': '1. Disassemble the binary\n2. Find the password comparison function\n3. Extract the hardcoded password\n4. Run the program with the correct password',
                    'hints': [
                        {'content': 'Look for string comparisons in the disassembly', 'cost': 25},
                        {'content': 'The password might be hardcoded in the binary', 'cost': 35}
                    ]
                },

                # MISC CHALLENGES (7)
                {
                    'title': 'QR Code Secret',
                    'description': 'This QR code contains more than meets the eye.',
                    'category': 'misc',
                    'difficulty': 'easy',
                    'points': 75,
                    'flag': 'CTF{qr_codes_are_cool}',
                    'answer_explanation': 'QR codes can store various types of data including text, URLs, and more.',
                    'solution_steps': '1. Scan the QR code with any QR reader\n2. The flag will be revealed in the decoded text\n3. Some QR codes might need special apps or contain encoded data',
                    'hints': [
                        {'content': 'Use any QR code scanner app or website', 'cost': 5},
                        {'content': 'The decoded text contains the flag directly', 'cost': 10}
                    ]
                },
                {
                    'title': 'Audio Steganography',
                    'description': 'This audio file sounds normal, but there\'s a hidden message.',
                    'category': 'misc',
                    'difficulty': 'medium',
                    'points': 175,
                    'flag': 'CTF{audio_steganography_master}',
                    'answer_explanation': 'Audio steganography hides data in sound files using various techniques.',
                    'solution_steps': '1. Use audio analysis tools like Audacity\n2. Look at the spectrogram view\n3. Check for hidden text in the frequency domain\n4. Try different audio filters and views',
                    'hints': [
                        {'content': 'Open the audio file in Audacity', 'cost': 15},
                        {'content': 'Switch to spectrogram view to see hidden text', 'cost': 25}
                    ]
                },

                # ADDITIONAL WEB CHALLENGES (8 more)
                {
                    'title': 'Local File Inclusion',
                    'description': 'This file viewer has a vulnerability. Can you read sensitive files?',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 225,
                    'flag': 'CTF{local_file_inclusion_success}',
                    'answer_explanation': 'LFI allows attackers to include local files on the server.',
                    'solution_steps': '1. Try including /etc/passwd\n2. Use ../ to traverse directories\n3. Look for flag.txt in various locations\n4. Try /var/www/flag.txt',
                    'hints': [
                        {'content': 'Try including system files like /etc/passwd', 'cost': 20},
                        {'content': 'Look for flag.txt in common web directories', 'cost': 30}
                    ]
                },
                {
                    'title': 'PHP Code Injection',
                    'description': 'This PHP eval() function looks dangerous. Can you exploit it?',
                    'category': 'web',
                    'difficulty': 'hard',
                    'points': 275,
                    'flag': 'CTF{php_code_injection_master}',
                    'answer_explanation': 'PHP eval() executes arbitrary PHP code, making it extremely dangerous.',
                    'solution_steps': '1. Inject PHP code: system("cat flag.txt")\n2. Or try: file_get_contents("flag.txt")\n3. Use semicolons to end statements properly\n4. Execute system commands to find the flag',
                    'hints': [
                        {'content': 'Try injecting PHP functions like system() or file_get_contents()', 'cost': 25},
                        {'content': 'Look for flag.txt using system commands', 'cost': 35}
                    ]
                },
                {
                    'title': 'XML External Entity (XXE)',
                    'description': 'This XML parser might be vulnerable to XXE attacks.',
                    'category': 'web',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{xxe_attack_successful}',
                    'answer_explanation': 'XXE attacks exploit XML parsers that process external entities.',
                    'solution_steps': '1. Create malicious XML with external entity\n2. Reference local files like /etc/passwd\n3. Use SYSTEM keyword to read files\n4. Extract the flag from server files',
                    'hints': [
                        {'content': 'Research XML External Entity (XXE) attacks', 'cost': 30},
                        {'content': 'Use SYSTEM entities to read local files', 'cost': 40}
                    ]
                },
                {
                    'title': 'Server-Side Template Injection',
                    'description': 'This template engine processes user input. Can you inject template code?',
                    'category': 'web',
                    'difficulty': 'hard',
                    'points': 325,
                    'flag': 'CTF{ssti_template_injection_pwned}',
                    'answer_explanation': 'SSTI occurs when user input is embedded in templates without proper sanitization.',
                    'solution_steps': '1. Test for template injection with {{7*7}}\n2. If it returns 49, try {{config}}\n3. Use template syntax to execute code\n4. Read files or execute commands to get flag',
                    'hints': [
                        {'content': 'Test with {{7*7}} to see if templates are processed', 'cost': 30},
                        {'content': 'Try {{config}} or similar template variables', 'cost': 40}
                    ]
                },

                # ADDITIONAL CRYPTO CHALLENGES (8 more)
                {
                    'title': 'Vigenère Cipher',
                    'description': 'Encrypted with key "CRYPTO": EEXGMXLKGGYIUOY',
                    'category': 'crypto',
                    'difficulty': 'medium',
                    'points': 150,
                    'flag': 'CTF{vigenere_solved}',
                    'answer_explanation': 'Vigenère cipher uses a repeating key to shift letters.',
                    'solution_steps': '1. Use the key "CRYPTO" to decrypt\n2. Each letter of the key shifts the corresponding plaintext letter\n3. Subtract the key letter value from ciphertext\n4. Use online Vigenère decoder with key',
                    'hints': [
                        {'content': 'The key is "CRYPTO" - use it with a Vigenère decoder', 'cost': 15},
                        {'content': 'Try an online Vigenère cipher decoder', 'cost': 20}
                    ]
                },
                {
                    'title': 'Substitution Cipher',
                    'description': 'Each letter is replaced: RGS{FHOFGVGHGVBA_PVCURE_PENPRXQ}',
                    'category': 'crypto',
                    'difficulty': 'medium',
                    'points': 175,
                    'flag': 'CTF{substitution_cipher_cracked}',
                    'answer_explanation': 'Substitution ciphers replace each letter with another letter consistently.',
                    'solution_steps': '1. Analyze letter frequency\n2. Look for common patterns like "THE"\n3. Use frequency analysis tools\n4. This is actually ROT13',
                    'hints': [
                        {'content': 'Try frequency analysis or common substitution patterns', 'cost': 15},
                        {'content': 'This might be a simple ROT cipher', 'cost': 25}
                    ]
                },
                {
                    'title': 'Atbash Cipher',
                    'description': 'Ancient cipher: XGU{ZGYZHS_XRKSVI_DLIPH}',
                    'category': 'crypto',
                    'difficulty': 'medium',
                    'points': 125,
                    'flag': 'CTF{atbash_cipher_works}',
                    'answer_explanation': 'Atbash cipher replaces A with Z, B with Y, etc.',
                    'solution_steps': '1. Recognize this as Atbash cipher\n2. Replace each letter with its opposite in alphabet\n3. A=Z, B=Y, C=X, etc.\n4. Decode to get the flag',
                    'hints': [
                        {'content': 'This is an Atbash cipher - A becomes Z, B becomes Y', 'cost': 10},
                        {'content': 'Replace each letter with its alphabet opposite', 'cost': 15}
                    ]
                },

                # ADDITIONAL FORENSICS CHALLENGES (6 more)
                {
                    'title': 'Network Packet Analysis',
                    'description': 'Analyze this network capture to find the hidden flag.',
                    'category': 'forensics',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{wireshark_packet_analysis}',
                    'answer_explanation': 'Network forensics involves analyzing packet captures to extract information.',
                    'solution_steps': '1. Open PCAP file in Wireshark\n2. Follow TCP streams\n3. Look for HTTP traffic or file transfers\n4. Extract files or search for flag strings',
                    'hints': [
                        {'content': 'Use Wireshark to analyze the packet capture', 'cost': 20},
                        {'content': 'Follow TCP streams to see full conversations', 'cost': 30}
                    ]
                },
                {
                    'title': 'File Carving',
                    'description': 'This disk image contains hidden files. Can you carve them out?',
                    'category': 'forensics',
                    'difficulty': 'hard',
                    'points': 275,
                    'flag': 'CTF{file_carving_expert}',
                    'answer_explanation': 'File carving recovers files from raw data without filesystem metadata.',
                    'solution_steps': '1. Use tools like foremost or scalpel\n2. Look for file signatures (magic bytes)\n3. Extract embedded files\n4. Search extracted files for the flag',
                    'hints': [
                        {'content': 'Use file carving tools like foremost or binwalk', 'cost': 25},
                        {'content': 'Look for embedded files or hidden archives', 'cost': 35}
                    ]
                },
                {
                    'title': 'Registry Analysis',
                    'description': 'This Windows registry hive contains important information.',
                    'category': 'forensics',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{registry_forensics_master}',
                    'answer_explanation': 'Windows registry contains system and application configuration data.',
                    'solution_steps': '1. Use tools like RegRipper or Registry Explorer\n2. Look for recently accessed files\n3. Check user activity and installed programs\n4. Search for flag in registry values',
                    'hints': [
                        {'content': 'Use registry analysis tools like RegRipper', 'cost': 30},
                        {'content': 'Look for user activity and recent file access', 'cost': 40}
                    ]
                },

                # ADDITIONAL REVERSE ENGINEERING CHALLENGES (6 more)
                {
                    'title': 'Assembly Analysis',
                    'description': 'This assembly code contains a flag. Can you understand it?',
                    'category': 'reverse',
                    'difficulty': 'medium',
                    'points': 225,
                    'flag': 'CTF{assembly_language_decoded}',
                    'answer_explanation': 'Assembly language is low-level code that directly corresponds to machine instructions.',
                    'solution_steps': '1. Read the assembly instructions\n2. Trace through the execution flow\n3. Understand register operations\n4. Find where the flag is constructed or revealed',
                    'hints': [
                        {'content': 'Trace through the assembly instructions step by step', 'cost': 20},
                        {'content': 'Look for string operations or character manipulation', 'cost': 30}
                    ]
                },
                {
                    'title': 'Packed Binary',
                    'description': 'This binary is packed. Unpack it to find the flag.',
                    'category': 'reverse',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{unpacked_binary_success}',
                    'answer_explanation': 'Packed binaries are compressed or encrypted to hide their true functionality.',
                    'solution_steps': '1. Identify the packer used (UPX, etc.)\n2. Use appropriate unpacking tools\n3. Analyze the unpacked binary\n4. Extract the flag from the unpacked code',
                    'hints': [
                        {'content': 'Identify the packer - might be UPX or similar', 'cost': 30},
                        {'content': 'Use unpacking tools or manual unpacking techniques', 'cost': 40}
                    ]
                },
                {
                    'title': 'Anti-Debug Bypass',
                    'description': 'This binary has anti-debugging measures. Can you bypass them?',
                    'category': 'reverse',
                    'difficulty': 'expert',
                    'points': 400,
                    'flag': 'CTF{anti_debug_bypassed}',
                    'answer_explanation': 'Anti-debugging techniques detect and prevent analysis tools.',
                    'solution_steps': '1. Identify anti-debug checks\n2. Patch or bypass the checks\n3. Use advanced debugging techniques\n4. Extract the flag after bypassing protections',
                    'hints': [
                        {'content': 'Look for IsDebuggerPresent() or similar API calls', 'cost': 35},
                        {'content': 'Patch the anti-debug checks or use advanced techniques', 'cost': 45}
                    ]
                },

                # ADDITIONAL MISC CHALLENGES (7 more)
                {
                    'title': 'Zip File Password',
                    'description': 'This ZIP file is password protected. Can you crack it?',
                    'category': 'misc',
                    'difficulty': 'medium',
                    'points': 150,
                    'flag': 'CTF{zip_password_cracked}',
                    'answer_explanation': 'ZIP passwords can be cracked using dictionary attacks or brute force.',
                    'solution_steps': '1. Use tools like john or hashcat\n2. Try common passwords first\n3. Use wordlists for dictionary attack\n4. Extract and read the flag file',
                    'hints': [
                        {'content': 'Try common passwords like "password" or "123456"', 'cost': 10},
                        {'content': 'Use john the ripper or similar password crackers', 'cost': 20}
                    ]
                },
                {
                    'title': 'Polyglot File',
                    'description': 'This file is both a valid image and something else. What is it?',
                    'category': 'misc',
                    'difficulty': 'medium',
                    'points': 175,
                    'flag': 'CTF{polyglot_file_discovered}',
                    'answer_explanation': 'Polyglot files are valid in multiple formats simultaneously.',
                    'solution_steps': '1. Check file signatures with hexdump\n2. Try opening as different file types\n3. Look for embedded data after image data\n4. Use binwalk to analyze file structure',
                    'hints': [
                        {'content': 'Check the file with hexdump or a hex editor', 'cost': 15},
                        {'content': 'Try opening the file as different formats', 'cost': 25}
                    ]
                },

                # FINAL EXPERT CHALLENGES (11 more to reach 45)
                {
                    'title': 'Advanced SQL Injection',
                    'description': 'This login has advanced protections. Can you still inject?',
                    'category': 'web',
                    'difficulty': 'expert',
                    'points': 400,
                    'flag': 'CTF{advanced_sqli_master}',
                    'answer_explanation': 'Advanced SQL injection bypasses basic protections using sophisticated techniques.',
                    'solution_steps': '1. Try union-based injection\n2. Use time-based blind injection\n3. Bypass WAF filters\n4. Extract data using advanced techniques',
                    'hints': [
                        {'content': 'Try union-based SQL injection techniques', 'cost': 35},
                        {'content': 'Consider time-based blind injection methods', 'cost': 45}
                    ]
                },
                {
                    'title': 'RSA Cryptography',
                    'description': 'Break this RSA encryption: n=143, e=7, c=123',
                    'category': 'crypto',
                    'difficulty': 'expert',
                    'points': 450,
                    'flag': 'CTF{rsa_factorization_success}',
                    'answer_explanation': 'RSA security depends on the difficulty of factoring large numbers.',
                    'solution_steps': '1. Factor n=143 (11*13)\n2. Calculate phi(n)=(11-1)*(13-1)=120\n3. Find d where e*d ≡ 1 (mod 120)\n4. Decrypt: m = c^d mod n',
                    'hints': [
                        {'content': 'Factor the modulus n=143 into prime factors', 'cost': 40},
                        {'content': 'Use the factorization to calculate the private key', 'cost': 50}
                    ]
                },
                {
                    'title': 'Buffer Overflow',
                    'description': 'This C program has a buffer overflow vulnerability.',
                    'category': 'pwn',
                    'difficulty': 'expert',
                    'points': 500,
                    'flag': 'CTF{buffer_overflow_exploited}',
                    'answer_explanation': 'Buffer overflows can overwrite return addresses to control program execution.',
                    'solution_steps': '1. Find the buffer overflow point\n2. Calculate offset to return address\n3. Craft payload to overwrite return address\n4. Execute shellcode or ROP chain',
                    'hints': [
                        {'content': 'Find the exact offset to overwrite the return address', 'cost': 45},
                        {'content': 'Use pattern generation tools to find the offset', 'cost': 55}
                    ]
                },
                {
                    'title': 'Kernel Exploitation',
                    'description': 'This kernel module has a vulnerability. Can you exploit it?',
                    'category': 'pwn',
                    'difficulty': 'expert',
                    'points': 600,
                    'flag': 'CTF{kernel_pwned_successfully}',
                    'answer_explanation': 'Kernel exploitation requires understanding of kernel internals and protection mechanisms.',
                    'solution_steps': '1. Analyze the kernel module\n2. Find the vulnerability (use-after-free, etc.)\n3. Develop exploit for privilege escalation\n4. Execute payload to get root access',
                    'hints': [
                        {'content': 'Look for memory corruption vulnerabilities', 'cost': 50},
                        {'content': 'Research kernel exploitation techniques', 'cost': 60}
                    ]
                },
                {
                    'title': 'Advanced Steganography',
                    'description': 'This image uses advanced steganographic techniques.',
                    'category': 'forensics',
                    'difficulty': 'expert',
                    'points': 375,
                    'flag': 'CTF{advanced_stego_decoded}',
                    'answer_explanation': 'Advanced steganography uses sophisticated algorithms to hide data.',
                    'solution_steps': '1. Try multiple steganography tools\n2. Check LSB (Least Significant Bit) encoding\n3. Use tools like StegSolve or zsteg\n4. Try different bit planes and color channels',
                    'hints': [
                        {'content': 'Use advanced stego tools like StegSolve or zsteg', 'cost': 35},
                        {'content': 'Check different bit planes and color channels', 'cost': 45}
                    ]
                },
                {
                    'title': 'Blockchain Analysis',
                    'description': 'Analyze this blockchain transaction to find the hidden message.',
                    'category': 'misc',
                    'difficulty': 'expert',
                    'points': 425,
                    'flag': 'CTF{blockchain_forensics_expert}',
                    'answer_explanation': 'Blockchain forensics involves analyzing transaction data and smart contracts.',
                    'solution_steps': '1. Decode the transaction data\n2. Look for hidden messages in transaction inputs\n3. Analyze smart contract code\n4. Extract the flag from blockchain data',
                    'hints': [
                        {'content': 'Look at the transaction input data for hidden messages', 'cost': 40},
                        {'content': 'Decode hex data in the transaction', 'cost': 50}
                    ]
                },
                {
                    'title': 'Machine Learning Evasion',
                    'description': 'Fool this ML model to classify your input as benign.',
                    'category': 'misc',
                    'difficulty': 'expert',
                    'points': 450,
                    'flag': 'CTF{ml_evasion_successful}',
                    'answer_explanation': 'ML evasion attacks craft inputs to fool machine learning models.',
                    'solution_steps': '1. Understand the ML model behavior\n2. Craft adversarial examples\n3. Use gradient-based attacks\n4. Successfully evade detection',
                    'hints': [
                        {'content': 'Research adversarial machine learning attacks', 'cost': 40},
                        {'content': 'Try small perturbations to fool the model', 'cost': 50}
                    ]
                },
                {
                    'title': 'Hardware Hacking',
                    'description': 'This firmware contains secrets. Can you extract them?',
                    'category': 'hardware',
                    'difficulty': 'expert',
                    'points': 475,
                    'flag': 'CTF{firmware_secrets_extracted}',
                    'answer_explanation': 'Hardware hacking involves analyzing firmware and embedded systems.',
                    'solution_steps': '1. Extract firmware from device\n2. Analyze firmware structure\n3. Use tools like binwalk and strings\n4. Find hardcoded secrets or backdoors',
                    'hints': [
                        {'content': 'Use binwalk to analyze the firmware structure', 'cost': 45},
                        {'content': 'Look for hardcoded passwords or keys', 'cost': 55}
                    ]
                },
                {
                    'title': 'Side Channel Attack',
                    'description': 'Use timing analysis to extract the secret key.',
                    'category': 'crypto',
                    'difficulty': 'expert',
                    'points': 500,
                    'flag': 'CTF{side_channel_timing_attack}',
                    'answer_explanation': 'Side channel attacks exploit physical information leakage.',
                    'solution_steps': '1. Measure timing differences\n2. Correlate timing with key bits\n3. Use statistical analysis\n4. Reconstruct the secret key',
                    'hints': [
                        {'content': 'Measure timing differences for different inputs', 'cost': 45},
                        {'content': 'Use statistical analysis to correlate timing with key bits', 'cost': 55}
                    ]
                },
                {
                    'title': 'Zero-Day Exploitation',
                    'description': 'Find and exploit a zero-day vulnerability in this application.',
                    'category': 'pwn',
                    'difficulty': 'expert',
                    'points': 750,
                    'flag': 'CTF{zero_day_exploited}',
                    'answer_explanation': 'Zero-day exploits target previously unknown vulnerabilities.',
                    'solution_steps': '1. Perform thorough code review\n2. Find novel vulnerability\n3. Develop working exploit\n4. Achieve code execution',
                    'hints': [
                        {'content': 'Look for unusual code patterns or edge cases', 'cost': 60},
                        {'content': 'Focus on input validation and memory management', 'cost': 70}
                    ]
                },
                {
                    'title': 'Ultimate Challenge',
                    'description': 'The final boss challenge. Combine all your skills to solve this.',
                    'category': 'misc',
                    'difficulty': 'expert',
                    'points': 1000,
                    'flag': 'CTF{ultimate_ctf_champion}',
                    'answer_explanation': 'This challenge requires mastery of multiple CTF categories and advanced techniques.',
                    'solution_steps': '1. Analyze all provided files\n2. Combine web, crypto, forensics, and reverse engineering\n3. Follow the multi-stage puzzle\n4. Demonstrate true CTF mastery',
                    'hints': [
                        {'content': 'This challenge combines multiple categories - start with reconnaissance', 'cost': 75},
                        {'content': 'Each stage unlocks the next - work systematically', 'cost': 100}
                    ]
                }
            ]
            
            print(f"📝 Creating {len(challenges_data)} challenges...")
            
            for i, challenge_data in enumerate(challenges_data, 1):
                # Create challenge
                challenge = Challenge(
                    title=challenge_data['title'],
                    description=challenge_data['description'],
                    category=challenge_data['category'],
                    difficulty=challenge_data['difficulty'],
                    points=challenge_data['points'],
                    flag_encrypted=challenge_data['flag'].encode(),
                    answer_explanation=challenge_data.get('answer_explanation', ''),
                    solution_steps=challenge_data.get('solution_steps', ''),
                    created_at=datetime.utcnow()
                )
                db.session.add(challenge)
                db.session.flush()  # Get the challenge ID
                
                # Create hints for this challenge
                if 'hints' in challenge_data:
                    for j, hint_data in enumerate(challenge_data['hints']):
                        hint = Hint(
                            challenge_id=challenge.id,
                            content=hint_data['content'],
                            cost=hint_data['cost'],
                            display_order=j + 1
                        )
                        db.session.add(hint)
                
                print(f"✅ Created challenge {i}: {challenge_data['title']}")
            
            # Commit all changes
            db.session.commit()
            print(f"\n🎉 Successfully created {len(challenges_data)} challenges with hints!")
            print("🎯 Ready to test your enhanced CTF platform!")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error creating challenges: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    return True

if __name__ == '__main__':
    success = create_comprehensive_challenges()
    if success:
        print("\n✅ Challenge creation completed!")
        print("🚀 Start your CTF application with: python app.py")
    else:
        print("\n❌ Challenge creation failed!")
        sys.exit(1)
