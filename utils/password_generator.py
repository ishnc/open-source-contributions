#!/usr/bin/env python3
"""
Secure Password Generator

A utility script to generate cryptographically secure passwords with customizable options.
Includes options for length, character sets, and exclusion of ambiguous characters.

Usage:
    python password_generator.py --length 16 --include-symbols --exclude-ambiguous

Author: ishan
License: MIT
"""

import argparse
import secrets
import string
from typing import List, Set


class PasswordGenerator:
    """A secure password generator with customizable options."""
    
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous_chars = "0O1lI|`'\""
    
    def generate_password(
        self,
        length: int = 12,
        include_lowercase: bool = True,
        include_uppercase: bool = True,
        include_digits: bool = True,
        include_symbols: bool = False,
        exclude_ambiguous: bool = False,
        min_of_each_type: bool = True
    ) -> str:
        """
        Generate a secure password with specified criteria.
        
        Args:
            length: Password length (minimum 4)
            include_lowercase: Include lowercase letters
            include_uppercase: Include uppercase letters
            include_digits: Include digits
            include_symbols: Include special symbols
            exclude_ambiguous: Exclude ambiguous characters (0, O, 1, l, I, |, `, ', ")
            min_of_each_type: Ensure at least one character from each selected type
        
        Returns:
            Generated password string
        
        Raises:
            ValueError: If invalid parameters are provided
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Build character set
        char_set = ""
        selected_types = []
        
        if include_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_set += chars
            selected_types.append(chars)
        
        if include_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_set += chars
            selected_types.append(chars)
        
        if include_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_set += chars
            selected_types.append(chars)
        
        if include_symbols:
            chars = self.symbols
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_set += chars
            selected_types.append(chars)
        
        if not char_set:
            raise ValueError("At least one character type must be included")
        
        # Generate password
        if min_of_each_type and len(selected_types) > 0:
            if length < len(selected_types):
                raise ValueError(f"Password length must be at least {len(selected_types)} when ensuring minimum of each type")
            
            # Ensure at least one character from each selected type
            password_chars = []
            for char_type in selected_types:
                password_chars.append(secrets.choice(char_type))
            
            # Fill remaining length with random characters from full set
            remaining_length = length - len(selected_types)
            for _ in range(remaining_length):
                password_chars.append(secrets.choice(char_set))
            
            # Shuffle the password to avoid predictable patterns
            password_list = list(password_chars)
            for i in range(len(password_list)):
                j = secrets.randbelow(len(password_list))
                password_list[i], password_list[j] = password_list[j], password_list[i]
            
            return ''.join(password_list)
        else:
            # Generate completely random password from character set
            return ''.join(secrets.choice(char_set) for _ in range(length))
    
    def generate_multiple_passwords(
        self,
        count: int,
        **kwargs
    ) -> List[str]:
        """Generate multiple passwords with the same criteria."""
        return [self.generate_password(**kwargs) for _ in range(count)]
    
    def check_password_strength(self, password: str) -> dict:
        """Analyze password strength and return metrics."""
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in self.symbols for c in password)
        
        character_types = sum([has_lower, has_upper, has_digit, has_symbol])
        
        # Simple strength calculation
        strength_score = 0
        if len(password) >= 8:
            strength_score += 1
        if len(password) >= 12:
            strength_score += 1
        if character_types >= 3:
            strength_score += 1
        if character_types == 4:
            strength_score += 1
        if len(password) >= 16:
            strength_score += 1
        
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
        strength = strength_levels[min(strength_score, 4)]
        
        return {
            "length": len(password),
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "character_types": character_types,
            "strength": strength,
            "strength_score": strength_score
        }


def main():
    parser = argparse.ArgumentParser(description="Generate secure passwords")
    parser.add_argument("-l", "--length", type=int, default=12,
                       help="Password length (default: 12)")
    parser.add_argument("-c", "--count", type=int, default=1,
                       help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-lowercase", action="store_true",
                       help="Exclude lowercase letters")
    parser.add_argument("--no-uppercase", action="store_true",
                       help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true",
                       help="Exclude digits")
    parser.add_argument("-s", "--include-symbols", action="store_true",
                       help="Include special symbols")
    parser.add_argument("-a", "--exclude-ambiguous", action="store_true",
                       help="Exclude ambiguous characters (0, O, 1, l, I, |, `, ', \")")
    parser.add_argument("--no-min-each", action="store_true",
                       help="Don't ensure minimum of each character type")
    parser.add_argument("--analyze", type=str,
                       help="Analyze strength of provided password")
    
    args = parser.parse_args()
    
    generator = PasswordGenerator()
    
    if args.analyze:
        analysis = generator.check_password_strength(args.analyze)
        print(f"Password Analysis for: {args.analyze}")
        print(f"Length: {analysis['length']}")
        print(f"Contains lowercase: {analysis['has_lowercase']}")
        print(f"Contains uppercase: {analysis['has_uppercase']}")
        print(f"Contains digits: {analysis['has_digits']}")
        print(f"Contains symbols: {analysis['has_symbols']}")
        print(f"Character types: {analysis['character_types']}/4")
        print(f"Strength: {analysis['strength']} ({analysis['strength_score']}/5)")
        return
    
    try:
        passwords = generator.generate_multiple_passwords(
            count=args.count,
            length=args.length,
            include_lowercase=not args.no_lowercase,
            include_uppercase=not args.no_uppercase,
            include_digits=not args.no_digits,
            include_symbols=args.include_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
            min_of_each_type=not args.no_min_each
        )
        
        if args.count == 1:
            print(passwords[0])
        else:
            for i, password in enumerate(passwords, 1):
                print(f"{i:2d}: {password}")
    
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
