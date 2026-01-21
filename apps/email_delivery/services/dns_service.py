"""
DNS Service for MX record resolution.
"""
import logging
import threading
import time
from typing import List, Tuple, Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


class DNSService:
    """
    Service for DNS operations, specifically MX record resolution.
    Includes caching to reduce DNS queries.
    """
    
    # Cache structure: {domain: (mx_records, timestamp, ttl)}
    _cache: dict = {}
    _cache_lock = threading.Lock()
    _default_ttl = 300  # 5 minutes default TTL
    
    @staticmethod
    def extract_domain_from_email(email: str) -> str:
        """
        Extract domain from email address.
        
        Args:
            email: Email address (e.g., 'user@example.com')
            
        Returns:
            Domain name (e.g., 'example.com')
        """
        if '@' not in email:
            raise ValueError(f"Invalid email address: {email}")
        return email.split('@')[1].lower().strip()
    
    @classmethod
    def get_mx_records(cls, domain: str, ttl: Optional[int] = None) -> List[Tuple[int, str]]:
        """
        Get MX records for a domain with caching.
        
        Args:
            domain: Domain name to query
            ttl: Cache TTL in seconds (default: 300)
            
        Returns:
            List of tuples (priority, hostname) sorted by priority (lower = higher priority)
            Example: [(10, 'mail1.example.com'), (20, 'mail2.example.com')]
        """
        domain = domain.lower().strip()
        cache_ttl = ttl or cls._default_ttl
        
        # Check cache first
        with cls._cache_lock:
            if domain in cls._cache:
                mx_records, cached_time, cached_ttl = cls._cache[domain]
                age = time.time() - cached_time
                if age < cached_ttl:
                    logger.debug(f"MX records for {domain} retrieved from cache")
                    return mx_records.copy()
                else:
                    # Cache expired, remove it
                    del cls._cache[domain]
        
        # Query DNS
        try:
            logger.info(f"Resolving MX records for domain: {domain}")
            answers = dns.resolver.resolve(domain, 'MX')
            
            mx_records = []
            for answer in answers:
                priority = answer.preference
                hostname = str(answer.exchange).rstrip('.')
                mx_records.append((priority, hostname))
            
            # Sort by priority (lower number = higher priority)
            mx_records.sort(key=lambda x: x[0])
            
            # Cache the results
            with cls._cache_lock:
                cls._cache[domain] = (mx_records, time.time(), cache_ttl)
            
            logger.info(f"Found {len(mx_records)} MX record(s) for {domain}: {mx_records}")
            return mx_records
            
        except dns.resolver.NXDOMAIN:
            error_msg = f"Domain {domain} does not exist (NXDOMAIN)"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except dns.resolver.NoAnswer:
            error_msg = f"No MX records found for domain {domain}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except dns.exception.DNSException as e:
            error_msg = f"DNS error resolving MX records for {domain}: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error resolving MX records for {domain}: {str(e)}"
            logger.error(error_msg)
            raise
    
    @classmethod
    def clear_cache(cls, domain: Optional[str] = None):
        """
        Clear MX record cache.
        
        Args:
            domain: Specific domain to clear, or None to clear all
        """
        with cls._cache_lock:
            if domain:
                domain = domain.lower().strip()
                if domain in cls._cache:
                    del cls._cache[domain]
                    logger.debug(f"Cleared cache for domain: {domain}")
            else:
                cls._cache.clear()
                logger.debug("Cleared all MX record cache")
