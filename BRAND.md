# AccordLock identity

AccordLock is an execution-control product for autonomous agents. Its public
identity must communicate precision, restraint, and operational clarity.

## Product description

Use this sentence when space permits:

> AccordLock checks each protected agent action against an approved task,
> relevant state commitments, available authority, and configured limits before
> dispatch.

Use this line for compact listings:

> Execution control for autonomous agents.

Do not call AccordLock an AI firewall, universal sandbox, compliance product,
or prompt-injection detector. These labels imply properties that the project
does not establish.

## Audience

Write for platform engineers, security engineers, SRE teams, agent-runtime
developers, and technical evaluators. A reader must be able to answer these
questions within one minute:

1. Which action does AccordLock control?
2. What does the runtime check?
3. Where does enforcement occur?
4. Which claims are implemented, tested, or still blocked?

## Mark

[`assets/accordlock-mark.svg`](assets/accordlock-mark.svg) is the canonical
public mark. It is an exact copy of the desktop artwork. It shows two flows
meeting at a transaction junction.

Preserve its geometry, colors, corner radius, and internal spacing. Do not
replace it with a shield, padlock, check mark, certificate seal, robot, or
model-provider logo. Do not put text inside the mark.

## Color

| Token | Value | Use |
| --- | --- | --- |
| Obsidian | `#111318` | Primary background and mark field |
| Porcelain | `#F4F1E9` | Primary text and trusted flow |
| Slate | `#7E8492` | Secondary text and observed flow |
| Signal | `#5264E8` | Transaction point and active state |
| Signal light | `#8491FF` | Signal gradient and focus state |
| Graphite | `#272B34` | Rules, borders, and secondary surfaces |

Red, amber, and green are status colors. Do not use them as brand accents.

## Type and layout

Use the platform system sans-serif for product and public documentation. Use a
system monospace face only for paths, identifiers, commands, and record values.

Use the transaction junction as the single recurring motif. Prefer one clear
diagram to a field of small cards. Use white space, short labels, and a
restrained color range. Avoid glass effects, generic security illustrations,
and decorative network graphs.

## Writing

Use the rules in [`LANGUAGE.md`](LANGUAGE.md). Put the product boundary near
the first capability claim. Put evidence beside the claim it supports. Do not
use assurance adjectives in place of evidence.

## Asset source

The root mark must retain the geometry and color of
`desktop/ui/desktop/src/images/icon.svg`. Update both assets in one reviewed
change.
