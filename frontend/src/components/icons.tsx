/**
 * SafeSOC — Icon Set
 * Small inline SVG icons shared by the nav, KPI cards, and widgets —
 * no icon-font/library dependency for a handful of simple glyphs.
 */

import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

const base = (props: IconProps) => ({
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.6,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
  ...props,
});

export const AlertIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 3 2 20h20L12 3z" />
    <path d="M12 10v4M12 17.5h.01" />
  </svg>
);

export const IncidentIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M4 12a8 8 0 1 0 8-8" />
    <path d="M4 4v4h4" />
    <path d="M12 8v4l3 2" />
  </svg>
);

export const EndpointIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="3" y="4" width="18" height="12" rx="1.5" />
    <path d="M8 20h8M12 16v4" />
  </svg>
);

export const ChainIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="3" y="9" width="7" height="7" rx="2" />
    <rect x="14" y="9" width="7" height="7" rx="2" />
    <path d="M10 12.5h4" />
  </svg>
);

export const TrendingIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M3 17 9 11l4 4 8-8" />
    <path d="M15 7h6v6" />
  </svg>
);

export const DashboardIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.2" />
    <rect x="13" y="3.5" width="7.5" height="4.5" rx="1.2" />
    <rect x="13" y="10.5" width="7.5" height="10" rx="1.2" />
    <rect x="3.5" y="13.5" width="7.5" height="7" rx="1.2" />
  </svg>
);

export const InvestigateIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="10.5" cy="10.5" r="6.5" />
    <path d="m20 20-4.3-4.3" />
  </svg>
);

export const SearchIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="10.5" cy="10.5" r="6.5" />
    <path d="m20 20-4.3-4.3" />
  </svg>
);

export const ChevronLeftIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M14 6l-6 6 6 6" />
  </svg>
);

export const ChevronRightIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M10 6l6 6-6 6" />
  </svg>
);

export const SortIcon = ({ direction, ...props }: IconProps & { direction: 'asc' | 'desc' | 'none' }) => (
  <svg {...base(props)} strokeWidth={2}>
    {direction !== 'desc' && <path d="M7 10l5-5 5 5" opacity={direction === 'asc' ? 1 : 0.35} />}
    {direction !== 'asc' && <path d="M7 14l5 5 5-5" opacity={direction === 'desc' ? 1 : 0.35} />}
  </svg>
);

export const SendIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M22 2 11 13" />
    <path d="M22 2 15 22l-4-9-9-4 20-7z" />
  </svg>
);

export const BotIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="4" y="8" width="16" height="11" rx="2.5" />
    <path d="M12 8V4M9 4h6" />
    <path d="M9 13.5h.01M15 13.5h.01" />
  </svg>
);

export const UsersIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 20c0-3 2.5-5.5 5.5-5.5s5.5 2.5 5.5 5.5" />
    <path d="M15.5 5.5c1.4.4 2.4 1.7 2.4 3.2 0 1.5-1 2.8-2.4 3.2" />
    <path d="M17.5 14.7c2 .6 3.5 2.5 3.5 4.8" />
  </svg>
);

export const LayersIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 3 3 8l9 5 9-5-9-5z" />
    <path d="M3 13l9 5 9-5" />
  </svg>
);

export const ComplianceIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 3.5 5 6v6c0 4.2 2.8 6.9 7 8.5 4.2-1.6 7-4.3 7-8.5V6l-7-2.5z" />
    <path d="m9 12 2 2 4-4.2" />
  </svg>
);

export const SoarIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M13 2 4 14h6l-1 8 9-12h-6l1-8z" />
  </svg>
);

export const CheckIcon = (props: IconProps) => (
  <svg {...base(props)} strokeWidth={2}>
    <path d="M5 12.5 9.5 17 19 7" />
  </svg>
);

export const XIcon = (props: IconProps) => (
  <svg {...base(props)} strokeWidth={2}>
    <path d="M6 6l12 12M18 6 6 18" />
  </svg>
);
