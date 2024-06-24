# drd00's CLI Password Manager
I am terrible at naming things. This aims to be a fast and minimal password manager written in C.

Cryptographic functions are provided by **libsodium**. The rest of program aims to provide a user interface, handling memory for secure password management.
That said, this is my first project using C (I had a lot of fun!), so I would **not** recommend using this seriously.

I intend to provide a CLI using ncurses, but this is a kind of minimal working version with a less visually appealing user interface.

## Compile from source
`make`. Requires `libbsd-dev` and `libsodium-dev` (e.g., from Ubuntu's repositories). 

May provide a binary in the future.

## Installation
To install, copy the executable to somewhere on PATH, e.g. `sudo cp ./passwordmanager /usr/bin/`.
