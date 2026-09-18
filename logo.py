#!/usr/bin/env python3
"""Super Logic AI — CLI banner. Node-network logo + wordmark, teal→orange gradient.

Usage: python3 logo.py
"""

ART = r"""
                 ●━━━━━━●
                        ┃
    ●                   ┃
    ┃        ●━━━━━━━━━━●
    ┃       ╱           ┃
    ●━━━━━●             ┃
    ┃                   ●
    ┃
    ●━━━━●
"""

# 3x5 block font, generated per letter so the wordmark can't have typos
FONT = {
    "S": ["███", "█  ", "███", "  █", "███"],
    "U": ["█ █", "█ █", "█ █", "█ █", "███"],
    "P": ["███", "█ █", "███", "█  ", "█  "],
    "E": ["███", "█  ", "██ ", "█  ", "███"],
    "R": ["███", "█ █", "██ ", "█ █", "█ █"],
    "L": ["█  ", "█  ", "█  ", "█  ", "███"],
    "O": ["███", "█ █", "█ █", "█ █", "███"],
    "G": ["███", "█  ", "█ █", "█ █", "███"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "C": ["███", "█  ", "█  ", "█  ", "███"],
    "A": ["███", "█ █", "███", "█ █", "█ █"],
    " ": ["  ", "  ", "  ", "  ", "  "],
}

def wordmark(text):
    rows = ["  " + " ".join(FONT[c][r] for c in text) for r in range(5)]
    return "\n".join(rows)

WORDMARK = wordmark("SUPER LOGIC AI")

# brand gradient: teal #00D09B (left) -> orange #FF7E1B (right)
G, T = (0, 208, 155), (255, 126, 27)

def paint(text):
    lines = text.strip("\n").split("\n")
    w = max(len(l) for l in lines) or 1
    out = []
    for line in lines:
        row = []
        for x, ch in enumerate(line):
            if ch == " ":
                row.append(ch)
                continue
            f = x / w
            r, g, b = (round(a + (b2 - a) * f) for a, b2 in zip(G, T))
            row.append(f"\033[38;2;{r};{g};{b}m{ch}")
        out.append("".join(row) + "\033[0m")
    return "\n".join(out)

if __name__ == "__main__":
    print(paint(ART))
    print(paint(WORDMARK))
    print()
