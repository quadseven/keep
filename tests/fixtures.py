def mac(last: int) -> str:
    """A MAC from the documentation range."""
    return f"00:00:5e:00:53:{last:02x}"


# Whois only accepts this range, so a documentation address cannot stand in.
TAILNET_CLIENT = "100.64.0.5"  # leak-guard-allow: reserved range, not a host
