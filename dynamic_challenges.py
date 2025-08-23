import base64
import hashlib
import random
import string
from PIL import Image, ImageDraw, ImageFont
import io
import os

def generate_crypto_base64_flag():
    """Generate a crypto challenge with base64 encoded flag"""
    # Generate random flag
    flag = f"CTF{{{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}}}"
    
    # Encode flag in base64
    encoded_flag = base64.b64encode(flag.encode()).decode()
    
    # Create challenge description
    description = f"""
    Crypto Challenge: Base64 Decoding
    
    You've intercepted an encoded message. Decode it to find the flag!
    
    Encoded message: {encoded_flag}
    
    Hint: This encoding is commonly used for binary data transmission.
    """
    
    return {
        'title': 'Base64 Decoder',
        'description': description,
        'flag': flag,
        'points': 100,
        'category': 'crypto',
        'difficulty': 'easy'
    }

def generate_stego_text_image():
    """Generate a steganography challenge with hidden text in image"""
    # Generate random flag
    flag = f"CTF{{{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}}}"
    
    # Create a simple image with hidden text
    img = Image.new('RGB', (400, 200), color='white')
    draw = ImageDraw.Draw(img)
    
    # Add some visible text
    try:
        # Try to use a default font
        font = ImageFont.load_default()
    except:
        font = None
    
    # Draw visible text
    draw.text((50, 50), "This image contains a hidden message", fill='black', font=font)
    draw.text((50, 100), "Look carefully for the secret flag", fill='black', font=font)
    
    # Add hidden text (very small, almost invisible)
    draw.text((10, 180), flag, fill='#fefefe', font=font)  # Almost white text
    
    # Convert to bytes
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    
    # Create challenge description
    description = f"""
    Steganography Challenge: Hidden in Plain Sight
    
    This image contains a hidden flag. Can you find it?
    
    Hint: Sometimes the secret is hidden in plain sight, just very subtly.
    """
    
    return {
        'title': 'Hidden Message',
        'description': description,
        'flag': flag,
        'points': 150,
        'category': 'stego',
        'difficulty': 'medium',
        'image_data': img_byte_arr
    }



def generate_random_challenge():
    """Generate a random challenge from available types"""
    challenge_types = [
        generate_crypto_base64_flag,
        generate_stego_text_image
    ]
    
    return random.choice(challenge_types)()
