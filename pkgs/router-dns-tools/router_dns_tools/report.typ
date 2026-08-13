// Router DNS activity report template.
// Compiled by router-report: a data.json with all aggregates is placed next
// to this file and loaded below — the document itself is static.
#let data = json("data.json")

#set document(title: data.meta.title)
#set page(margin: (x: 2cm, y: 2.2cm), footer: context [
  #set text(8pt, fill: gray)
  #data.meta.title — generated #data.meta.generatedAt
  #h(1fr)
  #counter(page).display("1 / 1", both: true)
])
#set text(font: "DejaVu Sans", 10pt)
#set heading(numbering: none)

#align(center)[
  #text(22pt, weight: "bold")[#data.meta.title]
  #v(0.3em)
  #text(11pt, fill: rgb("#555555"))[
    #data.meta.rangeStart — #data.meta.rangeEnd
  ]
]
#v(1.5em)

#let stat-tile(label, value) = box(
  fill: rgb("#f2f4f8"),
  radius: 4pt,
  inset: 10pt,
  width: 24%,
)[
  #text(16pt, weight: "bold")[#value]
  #linebreak()
  #text(9pt, fill: rgb("#555555"))[#label]
]

#if "overview" in data.sections [
  #let o = data.sections.overview
  #grid(
    columns: (1fr, 1fr, 1fr, 1fr),
    gutter: 8pt,
    stat-tile("Total queries", str(o.total)),
    stat-tile("Blocked", str(o.blocked)),
    stat-tile("Block rate", o.blockRate),
    stat-tile("Active clients", str(o.clients)),
  )
  #v(1.2em)
]

#let rank-table(title, rows, name-label) = [
  == #title
  #if rows.len() == 0 [
    #text(fill: gray)[No data recorded in this period.]
  ] else [
    #table(
      columns: (auto, 1fr, auto, auto),
      stroke: 0.5pt + rgb("#dddddd"),
      fill: (_, y) => if y == 0 { rgb("#f2f4f8") },
      table.header([*\#*], [*#name-label*], [*Queries*], [*Blocked*]),
      ..rows
        .enumerate()
        .map(((i, r)) => ([#(i + 1)], [#r.name], [#r.hits], [#r.blocked]))
        .flatten(),
    )
  ]
  #v(1em)
]

#if "topDomains" in data.sections {
  rank-table("Top domains", data.sections.topDomains, "Domain")
}
#if "topBlocked" in data.sections {
  rank-table("Top blocked domains", data.sections.topBlocked, "Domain")
}
#if "perGroup" in data.sections {
  rank-table("Activity by group", data.sections.perGroup, "Group")
}
#if "perDevice" in data.sections {
  rank-table("Activity by device", data.sections.perDevice, "Device")
}
#if "perUser" in data.sections {
  rank-table("Activity by user", data.sections.perUser, "User")
}
