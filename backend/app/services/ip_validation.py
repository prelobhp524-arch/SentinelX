import ipaddress


def canonicalize_public_ip(ip_address):
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string")

    try:
        address = ipaddress.ip_address(ip_address.strip())
    except (TypeError, ValueError):
        address = None

    if address is None:
        raise ValueError(f"Invalid IP address: {ip_address!r}")

    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(
            f"IP address is not globally routable: {ip_address!r}"
        )

    return address.compressed
