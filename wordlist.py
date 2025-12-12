"""
Word list for generating human-readable API key passphrases.
Curated list of common, short, phonetically distinct words optimized for CamelCase.
"""

PASSPHRASE_WORDS = [
    # Common objects and nature
    "Apple", "Bear", "Cloud", "Desert", "Eagle", "Forest", "Galaxy", "Harbor",
    "Island", "Jungle", "Kingdom", "Lighthouse", "Mountain", "Ocean", "Palace", "Quest",
    "River", "Storm", "Tiger", "Universe", "Valley", "Waterfall", "Wizard", "Zenith",

    # Colors and descriptive
    "Amber", "Bronze", "Crimson", "Diamond", "Emerald", "Frost", "Gold", "Harmony",
    "Indigo", "Jade", "Kite", "Lime", "Mauve", "Navy", "Onyx", "Pearl",
    "Quartz", "Ruby", "Scarlet", "Teal", "Umber", "Violet", "White", "Xray",

    # Animals
    "Antelope", "Badger", "Cheetah", "Dolphin", "Elephant", "Falcon", "Giraffe", "Hippo",
    "Ibis", "Jaguar", "Koala", "Lion", "Moose", "Narwhal", "Ostrich", "Panda",
    "Quail", "Raven", "Snake", "Turkey", "Urchin", "Vulture", "Whale", "Yak",

    # Action words and verbs
    "Accelerate", "Bounce", "Climb", "Dance", "Explore", "Fly", "Glide", "Hunt",
    "Inspire", "Jump", "Kick", "Launch", "Move", "Navigate", "Orbit", "Paddle",
    "Quicken", "Rush", "Soar", "Travel", "Unite", "Venture", "Wander", "Yield",

    # Elements and materials
    "Ash", "Brick", "Clay", "Dust", "Earth", "Fiber", "Glass", "Granite",
    "Ice", "Iron", "Lava", "Metal", "Ore", "Plastic", "Rock", "Sand",
    "Salt", "Silk", "Soil", "Steel", "Stone", "Tar", "Vapor", "Wood",

    # Time and celestial
    "Aurora", "Comet", "Dawn", "Dusk", "Eclipse", "Epoch", "Halo", "Luna",
    "Meteor", "Midnight", "Nova", "Orbit", "Planet", "Pulsar", "Quasar", "Saturn",
    "Solar", "Space", "Star", "Stellar", "Sun", "Supernova", "Twilight", "Venus",

    # Weather and water
    "Blizzard", "Breeze", "Cascade", "Cyclone", "Deluge", "Flurry", "Gale", "Gust",
    "Hail", "Haze", "Hurricane", "Mist", "Monsoon", "Puff", "Rain", "Sleet",
    "Snowstorm", "Squall", "Steam", "Surge", "Tempest", "Thunder", "Torrent", "Tornado",

    # Positive and abstract
    "Beacon", "Bliss", "Brave", "Bright", "Brilliant", "Calm", "Charm", "Clarity",
    "Comfort", "Courage", "Dawn", "Delight", "Dream", "Eden", "Essence", "Eternal",
    "Exalt", "Flair", "Gleam", "Glory", "Grace", "Grand", "Grant", "Guide",

    # Additional variety
    "Haven", "Heron", "Hidden", "Hollow", "Hopeful", "Horizon", "Humble", "Hybrid",
    "Ignite", "Illume", "Impact", "Import", "Impress", "Impulse", "Incite", "Income",
    "Index", "Indulge", "Inferno", "Inform", "Inhale", "Initiate", "Inkwell", "Innovate",
]

def generate_passphrase(num_words: int = 6) -> str:
    """
    Generate a random CamelCase passphrase from the word list.

    Args:
        num_words: Number of words to include (default: 6)

    Returns:
        A CamelCase passphrase string
    """
    import random
    return "".join(random.choice(PASSPHRASE_WORDS) for _ in range(num_words))
