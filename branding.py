def print_logo():
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        color = True
    except ImportError:
        color = False
    logo = r'''
     _/_/_/      _/    _/        _/_/          _/_/_/      _/_/_/_/_/      _/_/_/        _/_/_/_/        _/_/_/        _/_/        _/      _/   
  _/            _/    _/      _/    _/      _/                _/          _/    _/      _/            _/            _/    _/      _/_/    _/    
 _/  _/_/      _/_/_/_/      _/    _/        _/_/            _/          _/_/_/        _/_/_/        _/            _/    _/      _/  _/  _/     
_/    _/      _/    _/      _/    _/            _/          _/          _/    _/      _/            _/            _/    _/      _/    _/_/      
 _/_/_/      _/    _/        _/_/        _/_/_/            _/          _/    _/      _/_/_/_/        _/_/_/        _/_/        _/      _/       
                                                                                                                                                
                                                                                                                                                
'''
    tool_name = "GHOSTRECON"
    dev_credit = "Tool developed by: Youness Chregui Amin"
    if color:
        print(Fore.GREEN + logo + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + f"{'='*80}\n{tool_name.center(80)}\n{'='*80}" + Style.RESET_ALL)
        print(Fore.MAGENTA + dev_credit.center(80) + Style.RESET_ALL)
    else:
        print(logo)
        print(f"{'='*80}\n{tool_name.center(80)}\n{'='*80}")
        print(dev_credit.center(80))

def print_mode_menu():
    try:
        from colorama import Fore, Style
        color = True
    except ImportError:
        color = False
    menu = [
        ("[1] OSINT Mode", 'cyan'),
        ("[2] Attack Mode", 'red')
    ]
    print()
    for text, col in menu:
        if color:
            from colorama import Fore, Style
            color_val = getattr(Fore, col.upper(), Fore.WHITE)
            print(color_val + Style.BRIGHT + text + Style.RESET_ALL)
        else:
            print(text)
    print() 