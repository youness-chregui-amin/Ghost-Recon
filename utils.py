import logging

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False


def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def ctext(text, color):
    if COLORAMA:
        return f'{getattr(Fore, color.upper(), "")}'+text+f'{Style.RESET_ALL}'
    return text 