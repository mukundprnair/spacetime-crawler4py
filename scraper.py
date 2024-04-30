import hashlib
import time
from collections import defaultdict
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import re

# Global variables
visited_urls = set()  # To avoid revisiting URLs
unique_pages = set()  # Set for unique URLs
scraped_tokens = defaultdict(int)  # Store tokens for word frequencies
longest_page = {"url": None, "word_count": 0}  # Track longest page
subdomains = defaultdict(int)  # Track subdomains
stop_words = {"the", "and", "a", "of", "in", "to", "is", "for", "on", "with", "at", "by", "this", "that", "it", "or", "as", "from", "an"}  # Common stop words


# Tokenizer function to split text into individual tokens based on non-alphanumeric characters
def tokenize(text):
    words = ''.join([c.lower() if c.isalnum() else ' ' for c in text]).split()
    return words

# Function to compute word frequencies from the list of tokens
def compute_word_frequencies(tokens):
    frequencies = defaultdict(int)
    for token in tokens:
        frequencies[token] += 1
    return frequencies

# URL normalization
def normalize_url(url):
    parsed = urlparse(url)
    return urldefrag(parsed._replace(fragment='', query='').geturl()).url  # Remove query and fragment

# Check if the URL has invalid extensions
def has_invalid_extension(url):
    invalid_extensions = r".*\.(txt|css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$"
    return re.match(invalid_extensions, url.lower()) is not None

# URL validation
def is_valid(url):
    parsed = urlparse(url)

    # Define allowed domains with regex patterns
    allowed_domains = [r"\.ics\.uci\.edu", r"\.cs\.uci\.edu", r"\.informatics\.uci\.edu", r"\.stat\.uci\.edu"]
    domain_pattern = "|".join(allowed_domains)

    # Check if the domain is allowed
    if not re.search(rf".*({domain_pattern}).*", parsed.netloc):
        return False

    # Only allow HTTP or HTTPS
    if parsed.scheme not in {"http", "https"}:
        return False

    # Check if the URL has invalid extensions
    if has_invalid_extension(parsed.path):
        return False  # Avoid non-textual file types

    return True  # All checks passed

# Function to extract links
def extract_next_links(url, resp):
    extracted_links = set()  # Use a set to avoid duplicates

    if resp.status == 200:  # Only process if the response is successful
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

        # Extract links from common HTML tags and convert to absolute URLs
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href:
                absolute_link = normalize_url(urljoin(url, urldefrag(href).url))
                if not has_invalid_extension(absolute_link):  # Validate link
                    extracted_links.add(absolute_link)

        # Links from <link> tags
        for link_tag in soup.find_all('link', href=True):
            href = link_tag['href']
            if href:
                absolute_link = normalize_url(urljoin(url, urldefrag(href).url))
                if not has_invalid_extension(absolute_link):
                    extracted_links.add(absolute_link)

        # Links from <script> tags
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            if src:
                absolute_link = normalize_url(urljoin(url, urldefrag(src).url))
                if not has_invalid_extension(absolute_link):
                    extracted_links.add(absolute_link)

    return [link for link in extracted_links if is_valid(link)]

# Helper function to generate hashes
def generate_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

# Functions for trap detection
redirect_tracker = defaultdict(int)

def is_infinite_redirect(url):
    redirect_tracker[url] += 1
    return redirect_tracker[url] > 2  # Redirect limit to avoid traps

url_revisit_tracker = defaultdict(list)

def is_infinite_trap(url, revisit_threshold=10, time_window=60):
    current_time = time.time()
    url_revisit_tracker[url].append(current_time)

    # Remove old entries outside the time window
    url_revisit_tracker[url] = [
        t for t in url_revisit_tracker[url] if (current_time - t) < time_window
    ]

    return len(url_revisit_tracker[url]) > revisit_threshold  # High revisit frequency

def has_recursive_pattern(url):
    parsed = urlparse(url)
    path_segments = parsed.path.split("/")
    return len(set(path_segments)) < len(path_segments)

def has_too_many_query_parameters(url, max_parameters=5):
    parsed = urlparse(url)
    query_params = parsed.query.split("&")
    return len(query_params) > max_parameters

def is_large_file(resp):
    if not resp.raw_response:
        return False
    
    content_type = resp.raw_response.headers.get("Content-Type", "").lower()
    content_length = int(resp.raw_response.headers.get("Content-Length", "0"))

    non_textual_types = ["image", "video", "application"]
    large_file_size = 1000000  # 1 MB

    return any(t in content_type for t in non_textual_types) or content_length > large_file_size

# Scraper function with traps and updated validations
def scraper(url, resp):
    # Normalize URL and avoid revisits
    normalized_url = normalize_url(url)

    if normalized_url in visited_urls:
        return []

    # Handle infinite traps
    if is_infinite_trap(normalized_url) or is_infinite_redirect(normalized_url):
        return []

    # Handle large files and non-textual content
    if is_large_file(resp):
        return []  # Avoid large files

    # Avoid revisits and add to visited URLs
    visited_urls.add(normalized_url)

    if resp.status == 200:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

        # Detect and avoid dead URLs with no content
        page_text = soup.get_text(separator="\n")
        if not page_text.strip():
            return []

        # Check for unique pages based on the normalized URL
        if normalized_url in unique_pages:
            return []

        unique_pages.add(normalized_url)

        # Tokenize and store tokens for word frequencies
        tokens = tokenize(page_text)

        # tokens is a list, convert it into a dictionary with key=word and value=count
        for token in tokens:
            if token in scraped_tokens:
                scraped_tokens[token] += 1
            else:
                scraped_tokens[token] = 1
        # scraped_tokens.extend(tokens)

        # Update longest page if this one has more words
        word_count = len(tokens)
        if word_count > longest_page["word_count"]:
            longest_page["url"] = normalized_url
            longest_page["word_count"] = word_count


        # Extract valid links
        links = extract_next_links(normalized_url, resp)

        # Track subdomains for `ics.uci.edu`
        domain = urlparse(normalized_url).netloc
        if domain.endswith("ics.uci.edu"):
            subdomains[domain] += 1  # Increment subdomain count

        return [link for link in links if is_valid(link)]  # Return valid links

    return []  # Default return for non-200 status codes
