from configparser import ConfigParser
from argparse import ArgumentParser
from scraper import unique_pages, longest_page, compute_word_frequencies, scraped_tokens, subdomains
from utils.server_registration import get_cache_server
from utils.config import Config
from crawler import Crawler
import time

# Function to print the total unique pages
def print_unique_pages():
    print(f"Total unique pages: {len(unique_pages)}")

# Function to print the longest page by word count
def print_longest_page():
    if longest_page["url"]:
        print(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words")

# Function to print the 50 most common words
def print_common_words():
    #frequencies = compute_word_frequencies(scraped_tokens)
    frequencies = scraped_tokens
    # common_words = sorted(frequencies.items(), key=lambda x: (-x[1], x[0]))[:50]  # Top 50 common words
    common_words = sorted(frequencies.items(), key=lambda item: -item[1])  # list of tuples
    to_print = list()
    
    for i in range(50):
        to_print.append(common_words[i])
    print("50 most common words:")
    print(to_print)
    # for word, freq in common_words:
    #     print(f"{word}: {freq}")

# Function to print subdomains in `ics.uci.edu`
def print_subdomains():
    print("Subdomains in ics.uci.edu:")
    for subdomain, count in sorted(subdomains.items()):
        print(f"{subdomain}: {count}")

# Main function to start the crawler and then print the results
def main(config_file, restart):
    cparser = ConfigParser()
    cparser.read(config_file)
    config = Config(cparser)
    config.cache_server = get_cache_server(config, restart)
    crawler = Crawler(config, restart)
    crawler.start()
    crawler.join()  # Wait for the crawler to finish

    print_unique_pages()  # Print unique pages
    print_longest_page()  # Print longest page
    print_common_words()  # Print common words
    print_subdomains()  # Print subdomains

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--restart", action="store_true", default=False)
    parser.add_argument("--config_file", type=str, default="config.ini")
    args = parser.parse_args()
    main(args.config_file, args.restart)
