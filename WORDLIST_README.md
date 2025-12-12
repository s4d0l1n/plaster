# Wordlist Configuration for Plaster API Keys

The Plaster system now generates human-readable passphrases for API keys using a customizable word list.

## How It Works

- API keys are generated as 6-word CamelCase passphrases
- Example: `WoodStellarTurkeyTwilightClimbAurora`
- Words are read from `wordlist.txt` (one word per line)

## Using Your Own Wordlist

You can replace the included `wordlist.txt` with any word list from the internet.

### Recommended Sources

Popular word lists for passphrase generation:

1. **EFF Wordlist** (Official, recommended)
   - https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
   - Use either the long list or short list (4-6 char words work best)
   - Download: Save the list as `wordlist.txt`

2. **Diceware Wordlist**
   - https://diceware.rempe.us/
   - Classic 7776-word list
   - Extract just the words into your `wordlist.txt`

3. **English Dictionary Lists**
   - Any common English word list works
   - ~5000-10000 words is ideal

### Steps to Replace Wordlist

**Option 1: Direct File Replacement**

```bash
# Download or create your wordlist
curl -o wordlist.txt https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

# Extract just the words if needed (wordlist might have format like "1-word1" "2-word2")
# For EFF list, extract second column:
awk '{print $2}' eff_large_wordlist.txt > wordlist.txt

# Place in plaster directory
cp wordlist.txt /home/crankykong/Documents/plaster_docker/plaster/

# Rebuild Docker
cd /home/crankykong/Documents/plaster_docker/plaster
docker compose down && docker compose up -d --build
```

**Option 2: Manual Creation**

```bash
# Create wordlist.txt with your words (one per line, lowercase)
cat > wordlist.txt << 'EOF'
apple
bear
cloud
database
elephant
...
EOF

# Save and rebuild
docker compose down && docker compose up -d --build
```

## Wordlist Format

- **One word per line**
- **Lowercase** (the system automatically capitalizes)
- **No special characters**
- **4-8 character words preferred** (for readable passphrases)
- Minimum recommended: 1000 words
- Ideal: 5000-10000 words

### Example Format

```
apple
bear
cloud
desert
eagle
forest
```

## Entropy Calculation

With your wordlist:

- **Words in list**: N
- **Words per passphrase**: 6
- **Entropy bits**: 6 × log₂(N)

Examples:
- 214 words (included) = 48 bits entropy
- 1000 words = 60 bits entropy
- 5000 words = 72 bits entropy
- 10000 words = 80 bits entropy

**Recommendation**: 5000+ words for maximum entropy

## File Locations

The system looks for `wordlist.txt` in these locations (in order):

1. Same directory as `plaster_server.py` (local development)
2. `/app/wordlist.txt` (Docker container)
3. `/usr/local/bin/wordlist.txt` (Installed version)
4. `~/.plaster/wordlist.txt` (User home directory)

## Testing Your Wordlist

```bash
# Generate a test key to verify wordlist is loaded
curl -s -X POST "http://localhost:9321/auth/generate" \
  -H "Content-Type: application/json" | jq '.api_key'

# Should output a 6-word CamelCase passphrase
# Example: AppleBearCloudDesertEagleForest
```

## Example Generated Passphrases

**With included 214-word list:**
- `WoodStellarTurkeyTwilightClimbAurora`
- `ZenithGlideNavigateHurricaneCrimsonLion`
- `KickAshForestExaltDesertQuartz`
- `AccelerateGraniteVultureBlissEagleRush`

## Error Handling

If `wordlist.txt` is missing:

```
Error: wordlist.txt not found. Please ensure wordlist.txt is in the
same directory as the script or in /app/
```

**Solution**: Ensure `wordlist.txt` exists and is readable in one of the locations listed above.

## Notes

- The system automatically capitalizes all words
- Passphrases are case-insensitive (for API key matching)
- Each key is unique due to random word selection
- No special characters needed in wordlist (except hyphens if desired)
