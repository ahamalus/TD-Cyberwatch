/**
 * Chart components (Recharts). Each chart handles empty data, offers a
 * tabular alternative for screen readers and keyboard users, and uses the
 * restrained semantic palette from the design tokens.
 */
import { Box, Group, SegmentedControl, Table, Text, useComputedColorScheme } from "@mantine/core";
import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { palette } from "../design/tokens";
import { EmptyState } from "./ui";

export interface Series {
  key: string;
  label: string;
  color: string;
}

export const SERIES_COLORS = {
  critical: "#B93535",
  high: palette.threatRed,
  medium: palette.warningAmber,
  low: palette.infoCyan,
  informational: palette.slateGrey,
  ok: palette.secureGreen,
  warn: palette.warningAmber,
  bad: palette.threatRed,
  blue: palette.cyberBlue,
};

function useAxisColors() {
  const scheme = useComputedColorScheme("light");
  return scheme === "dark"
    ? { grid: "#22314b", text: "#94a3b8", tooltipBg: "#111B2E", tooltipBorder: "#22314b" }
    : { grid: "#E2E8F0", text: "#64748B", tooltipBg: "#FFFFFF", tooltipBorder: "#E2E8F0" };
}

export function StackedBars({
  data,
  series,
  height = 220,
  label,
}: {
  data: Record<string, Record<string, number>>;
  series: Series[];
  height?: number;
  label: string;
}) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const c = useAxisColors();
  const rows: Record<string, string | number>[] = Object.entries(data)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([day, v]) => ({ day: day.slice(5), ...Object.fromEntries(series.map((s) => [s.key, v[s.key] ?? 0])) }));
  const total = rows.reduce((acc, r) => acc + series.reduce((a, s) => a + Number(r[s.key] ?? 0), 0), 0);
  return (
    <Box>
      <Group justify="flex-end" mb={4}>
        <SegmentedControl
          size="xs"
          value={view}
          onChange={(v) => setView(v as "chart" | "table")}
          data={[
            { label: "Chart", value: "chart" },
            { label: "Table", value: "table" },
          ]}
          aria-label={`${label}: display as`}
        />
      </Group>
      {total === 0 ? (
        <EmptyState title="No data in this period" description="Values appear here once monitoring has recorded results." />
      ) : view === "chart" ? (
        <Box role="img" aria-label={`${label}. ${total} total in the period. Use the Table view for exact values.`} h={height}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
              <CartesianGrid stroke={c.grid} vertical={false} />
              <XAxis dataKey="day" tick={{ fill: c.text, fontSize: 11 }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
              <YAxis allowDecimals={false} tick={{ fill: c.text, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                cursor={{ fill: "rgba(22,119,255,0.06)" }}
                contentStyle={{ background: c.tooltipBg, border: `1px solid ${c.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
              />
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: c.text }} />
              {series.map((s) => (
                <Bar key={s.key} dataKey={s.key} name={s.label} stackId="a" fill={s.color} maxBarSize={22} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </Box>
      ) : (
        <div className="cw-table-scroll">
          <Table fz="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Date</Table.Th>
                {series.map((s) => (
                  <Table.Th key={s.key}>{s.label}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((r) => (
                <Table.Tr key={r.day}>
                  <Table.Td>{r.day}</Table.Td>
                  {series.map((s) => (
                    <Table.Td key={s.key}>{r[s.key]}</Table.Td>
                  ))}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
      )}
    </Box>
  );
}

export function Donut({ data, label, height = 180 }: { data: { name: string; value: number; color: string }[]; label: string; height?: number }) {
  const total = data.reduce((a, d) => a + d.value, 0);
  if (total === 0) return <EmptyState title="No data yet" />;
  return (
    <Group wrap="nowrap" gap="md" align="center">
      <Box w={height} h={height} role="img" aria-label={`${label}: ${data.map((d) => `${d.name} ${d.value}`).join(", ")}`}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius="62%" outerRadius="95%" paddingAngle={2} isAnimationActive={false}>
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} stroke="none" />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </Box>
      <Box>
        {data.map((d) => (
          <Group key={d.name} gap={8} mb={4} wrap="nowrap">
            <Box w={10} h={10} style={{ borderRadius: 3, background: d.color, flexShrink: 0 }} aria-hidden />
            <Text size="sm">
              {d.name}: <b>{d.value}</b>
            </Text>
          </Group>
        ))}
      </Box>
    </Group>
  );
}
