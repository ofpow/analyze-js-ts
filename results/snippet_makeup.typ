#set page(paper: "a4", flipped: true)
#set heading(numbering: "1.")



#import "@preview/cetz:0.3.4"
#import cetz.draw: *

#let datasets = (
  ("Agentic JS", 29.65, 6.32, 64.04),
  ("Agentic TS", 55.80, 5.69, 38.51),
  ("Chat JS (single)", 71.22, 21.49, 7.30),
  ("Chat JS (multi)", 58.93, 20.17, 20.90),
  ("Chat TS (single)", 75.35, 15.73, 8.92),
  ("Chat TS (multi)", 59.74, 13.64, 26.62),
  ("Stack v1 JS", 70.40, 28.60, 1.00),
  ("Stack v1 TS", 83.17, 13.97, 2.87),
  ("CodeSearchNet", 71.21, 28.74, 0.05),
)

#let clean-color = rgb("#31966B")
#let defective-color = rgb("#E9A23B")
#let errors-color = rgb("#D85A5A")
#let grid-color = rgb("#CCCCCC")

#let chart-width = 20
#let bar-height = 0.55
#let row-gap = 0.55
#let label-width = 2.5
#let chart-height = 9 * (bar-height + row-gap)

#figure(
  cetz.canvas({
    // Grid lines and percentage labels.
    for p in range(0, 101, step: 20) {
      let x = chart-width * p / 100

      line(
        (x, 0.5),
        (x, -chart-height + 0.5),
        stroke: (
          paint: grid-color,
          thickness: 0.5pt,
          dash: "dotted",
        ),
      )

      content(
        (x, 0.85),
        anchor: "south",
        text(size: 12pt, str(p) + "%"),
      )
    }

    // Dataset bars.
    for i in range(9) {
      let (name, clean, defective, errors) = datasets.at(i)
      let y = -i * (bar-height + row-gap)

      // Dataset label.
      content(
        (-0.2, y),
        anchor: "east",
        text(size: 12pt, name),
      )

      // Segment widths.
      let values = (clean, defective, errors)
      let palette = (
        clean-color,
        defective-color,
        errors-color,
      )

      let x = 0.0

      for j in range(3) {
  let value = values.at(j)
  let w = chart-width * value / 100

  rect(
    (x, y - bar-height / 2),
    (x + w, y + bar-height / 2),
    fill: palette.at(j),
    stroke: none,
  )

  // Percentage label inside the bar.
  if value >= 5 {
    content(
      (x + w / 2, y),
      anchor: "center",
      text(
        size: 12pt,
        fill: white,
        weight: "bold",
        str(value) + "%",
      ),
    )
  }

  x += w
}
    }
  }),
  caption: [
    Distribution of scanned snippets by quality category.
    Green: clean, orange: defective, red: errors.
  ],
)

