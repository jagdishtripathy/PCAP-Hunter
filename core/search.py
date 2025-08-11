import re
from config.patterns import COMPILED_PATTERNS, FLAG_PATTERNS, CRYPTO_PATTERNS, KEYWORD_PATTERNS
import logging

log = logging.getLogger(__name__)

def search_for_flags(payload: str, search_type: str = "all") -> dict:
    """
    Search for flags, crypto patterns, and keywords in payload
    
    Args:
        payload: Text payload to search
        search_type: Type of search ("flags", "crypto", "keywords", "all")
    
    Returns:
        Dictionary with search results by category
    """
    if search_type not in COMPILED_PATTERNS:
        search_type = "all"
    
    results = {
        "flags": [],
        "crypto": [],
        "keywords": [],
        "all": []
    }
    
    # Search for flags
    for pattern in COMPILED_PATTERNS["flags"]:
        matches = pattern.findall(payload)
        results["flags"].extend(matches)
        results["all"].extend(matches)
    
    # Search for crypto patterns
    for pattern in COMPILED_PATTERNS["crypto"]:
        matches = pattern.findall(payload)
        results["crypto"].extend(matches)
        results["all"].extend(matches)
    
    # Search for keywords
    for pattern in COMPILED_PATTERNS["keywords"]:
        matches = pattern.findall(payload, re.IGNORECASE)
        results["keywords"].extend(matches)
        results["all"].extend(matches)
    
    # Remove duplicates while preserving order
    for key in results:
        seen = set()
        unique_results = []
        for item in results[key]:
            if item not in seen:
                seen.add(item)
                unique_results.append(item)
        results[key] = unique_results
    
    log.debug(f"Search results: {results}")
    return results

def search_for_keyword(payload: str, keyword: str) -> list:
    """
    Search for a specific keyword in payload
    
    Args:
        payload: Text payload to search
        keyword: Keyword to search for
    
    Returns:
        List of matches with context
    """
    if not keyword:
        return []
    
    matches = []
    # Create a pattern that captures context around the keyword
    pattern = re.compile(f"(.{{0,50}})({re.escape(keyword)})(.{{0,50}})", re.IGNORECASE)
    
    for match in pattern.finditer(payload):
        context = match.group(1) + "[" + match.group(2) + "]" + match.group(3)
        matches.append({
            "keyword": match.group(2),
            "context": context,
            "start": match.start(),
            "end": match.end()
        })
    
    log.debug(f"Keyword '{keyword}' found {len(matches)} times")
    return matches

def search_for_custom_pattern(payload: str, custom_pattern: str) -> list:
    """
    Search for a custom regex pattern in payload
    
    Args:
        payload: Text payload to search
        custom_pattern: Custom regex pattern
    
    Returns:
        List of matches
    """
    try:
        pattern = re.compile(custom_pattern)
        matches = pattern.findall(payload)
        log.debug(f"Custom pattern found {len(matches)} matches")
        return matches
    except re.error as e:
        log.error(f"Invalid regex pattern: {e}")
        return []