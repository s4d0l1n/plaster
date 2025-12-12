"""
Word list for generating human-readable API key passphrases.
Reads words from wordlist.txt file.
"""

import random
from pathlib import Path

def load_words() -> list:
    """
    Load words from wordlist.txt file.
    Tries multiple paths to find the wordlist file.

    Returns:
        List of words, or empty list if file not found
    """
    # Try different paths where wordlist.txt might be located
    possible_paths = [
        Path(__file__).parent / "wordlist.txt",  # Same directory as this script
        Path("/app/wordlist.txt"),               # Docker container path
        Path("/usr/local/bin/wordlist.txt"),     # Installed path
        Path.home() / ".plaster" / "wordlist.txt"  # User home
    ]

    for path in possible_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    # Read lines, strip whitespace, filter empty lines
                    # Capitalize each word (CamelCase)
                    words = [line.strip().capitalize() for line in f if line.strip()]
                    if words:
                        return words
            except Exception as e:
                print(f"Warning: Failed to read {path}: {e}")

    # Fallback: Return empty list and let caller handle it
    return []

# Load words at module initialization
PASSPHRASE_WORDS = load_words()

def generate_passphrase(num_words: int = 6) -> str:
    """
    Generate a random CamelCase passphrase from the word list.

    Args:
        num_words: Number of words to include (default: 6)

    Returns:
        A CamelCase passphrase string

    Raises:
        RuntimeError: If no words could be loaded from wordlist.txt
    """
    if not PASSPHRASE_WORDS:
        raise RuntimeError("Error: wordlist.txt not found. Please ensure wordlist.txt is in the same directory as the script or in /app/")

    return "".join(random.choice(PASSPHRASE_WORDS) for _ in range(num_words))
