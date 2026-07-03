import Charts
import SwiftUI

/// Burn history — an area chart over the series buckets, in the fuse's amber,
/// with a faint fill and an emphasized endpoint. A `compact` variant is a
/// chromeless sparkline for the fleet hero.
struct BurnChart: View {
    let buckets: [SeriesBucket]
    var compact = false

    private var indexed: [(index: Int, cost: Double)] {
        buckets.enumerated().map { ($0.offset, $0.element.cost) }
    }
    private var lastIndex: Int { max(0, buckets.count - 1) }
    private var lastCost: Double { buckets.last?.cost ?? 0 }

    var body: some View {
        Chart {
            ForEach(indexed, id: \.index) { point in
                AreaMark(
                    x: .value("t", point.index),
                    y: .value("cost", point.cost)
                )
                .interpolationMethod(.monotone)
                .foregroundStyle(
                    LinearGradient(colors: [Palette.amber.opacity(0.35), .clear],
                                   startPoint: .top, endPoint: .bottom)
                )
                LineMark(
                    x: .value("t", point.index),
                    y: .value("cost", point.cost)
                )
                .interpolationMethod(.monotone)
                .foregroundStyle(Palette.amber)
                .lineStyle(StrokeStyle(lineWidth: 2))
            }
            if lastCost > 0 {
                PointMark(x: .value("t", lastIndex), y: .value("cost", lastCost))
                    .foregroundStyle(Palette.ember)
                    .symbolSize(compact ? 26 : 46)
            }
        }
        .chartXAxis(.hidden)
        .chartYAxis(compact ? .hidden : .automatic)
        .chartYScale(domain: .automatic(includesZero: true))
        .frame(height: compact ? 48 : 120)
    }
}
