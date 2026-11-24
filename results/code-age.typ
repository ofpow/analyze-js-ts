
#import "@preview/cetz:0.3.4": canvas, draw

#let categories = (
  "pre es2015",
  "es2015-16",
  "es2017-19",
  "es2020+",
)

#let datasets = (
  ("Agentic JS", (38.9, 40.5, 14.3, 6.2)),
  ("Agentic TS", (28.5, 36.3, 15.1, 20.1)),
  ("Chat JS (single)", (11.3, 56.5, 23.1, 9.1)),
  ("Chat JS (multi)", (10.8, 53.6, 25.0, 10.6)),
  ("Chat TS (single)", (8.8, 38.6, 30.4, 22.2)),
  ("Chat TS (multi)", (7.9, 33.9, 29.4, 28.8)),
  ("Human JS", (36.2, 48.6, 10.4, 4.8)),
  ("Human TS", (3.8, 52.7, 13.6, 29.9)),
  ("CodeSearchNet", (75.7, 21.8, 21.8, 0.3)),
)

#let colors = (
  rgb("#E15759"),
  rgb("#4E79A7"),
  rgb("#F28E2B"),
  rgb("#59A14F"),
)

#let bar-height = 0.48
#let bar-gap = 0.30
#let chart-width = 12
#let label-width = 2.0
#let chart-height = 9 * (bar-height + bar-gap)

#set page(
  width: 17cm,
  height: 12cm,
  margin: 0.8cm,
)

#align(center)[
  #text(size: 15pt, weight: "bold")[
    ECMAScript Version Distribution
  ]
]

#v(0.5cm)

#canvas(length: 1cm, {
  import draw: *

  // Horizontal axis and grid lines
  for i in range(0, 6) {
    let x = label-width + chart-width * i / 5

    line(
      (x, 0),
      (x, -chart-height - 0.2),
      stroke: (
        paint: gray,
        thickness: 0.4pt,
        dash: "dashed",
      ),
    )

    content(
      (x, 0.35),
      text(size: 8pt)[#(i * 20)%],
      anchor: "south",
    )
  }

  // Stacked bars
  for (i, dataset) in datasets.enumerate() {
    let y = -i * (bar-height + bar-gap) - 0.25
    let values = dataset.at(1)
    let total = values.sum()

    content(
      (label-width - 0.15, y - bar-height / 2),
      text(size: 8pt)[#dataset.at(0)],
      anchor: "east",
    )

    // Draw each segment
    for (j, value) in values.enumerate() {
      let offset = if j == 0 {
  0
} else {
  chart-width * values.slice(0, j).sum() / total
}

      let segment-width = chart-width * value / total

      rect(
        (label-width + offset, y - bar-height / 2),
        (
          label-width + offset + segment-width,
          y + bar-height / 2,
        ),
        fill: colors.at(j),
        stroke: white,
      )

      // Percentage labels
      if segment-width > 0.45 {
        content(
          (
            label-width + offset + segment-width / 2,
            y,
          ),
          text(
            size: 7pt,
            fill: white,
            weight: "bold",
          )[
            #str(value)%
          ],
          anchor: "center",
        )
      }
    }
  }
})

#v(0.3cm)

// Legend
#align(center)[
  #grid(
    columns: 4,
    column-gutter: 0.5cm,
    row-gutter: 0.15cm,
    ..categories.enumerate().map(((i, category)) => [
      #box(
        width: 0.25cm,
        height: 0.25cm,
        fill: colors.at(i),
      )
      #text(size: 8pt)[#category]
    ]),
  )
]

