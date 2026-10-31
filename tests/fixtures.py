from ipaddress import ip_network


def mac(last: int) -> str:
    """A MAC from the documentation range."""
    return f"00:00:5e:00:53:{last:02x}"


TAILNET_CLIENT = "198.51.100.5"
TEST_TAILNET = (ip_network("198.51.100.0/24"),)
