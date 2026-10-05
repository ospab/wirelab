# wirelab panel: design

**Product.** A local control panel for a running lab: three containers,
client, wire and server.
**Audience.** One person who develops or tests a transport protocol and
knows networking. Uses it on a laptop next to an editor, often for hours.
**Main task.** Run your own binary in the client and server consoles, and
see and shape what passes over the wire between them.

## Layout

Three columns in the order traffic flows: client, wire, server. The wire is
the narrow middle column and the only one with controls; the consoles take
the rest of the width evenly. Below 900 px the columns stack in the same
order and each console gets a fixed height.

No header bar. The lab id, its state and the stop command sit in one line
at the top of the wire column, because that is the column about the lab
itself.

## Colors

| Name | Hex | Role |
|---|---|---|
| paper | `#f4f1ea` | page background (light) |
| ink | `#1d1c1a` | text; console background in both themes |
| rule | `#cfc8b8` | borders, separators |
| c2s | `#b5651d` | everything client→server: labels, rows, counters |
| s2c | `#2f6f73` | everything server→client |
| alarm | `#a3271f` | a secret found in clear, a failed command |

Dark theme: paper becomes `#191816`, ink text `#e8e3d8`, rule `#3a3732`; c2s
and s2c lighten to `#d08a4a` and `#5fa3a6`. The consoles are always ink: a
terminal that turns light with the page breaks every program's colors.

Direction color is the one accent. It is never used for decoration, only
to say which way a byte went.

## Type

- IBM Plex Sans (has Cyrillic): interface text, 14 px, labels 12 px.
- IBM Plex Mono: consoles, addresses, packet rows, numbers. Numbers are
  tabular so counters do not jitter.

## Principles

1. The wire column shows observations, not interpretations. A packet row
   is time, direction, size, ports, and what a dissector actually parsed
   (SNI, "TLS ClientHello"). Nothing guesses the protocol.
2. Controls change exactly what they name and take effect when applied.
   The current netem line per direction is shown verbatim as `tc` holds it.
3. Every change and every console byte goes to the session folder; the
   panel says where that folder is.

## Rejected defaults

Dark neon "hacker" palette, glowing accents, cards with shadows around each
console, a hero header with the product name. Borders are 1 px rules; radii
are 0 except on inputs (2 px).
