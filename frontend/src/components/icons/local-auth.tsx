import type { SVGProps } from "react";

export function LocalAuthIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
      {...props}
    >
      <path
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0-8 0M6 21v-2a4 4 0 0 1 4-4h5m3.5 3.5L15 22l-1.5-1.5m5.054-2.086a2 2 0 1 1 2.828-2.828a2 2 0 0 1-2.828 2.828M16 19l1 1"
      ></path>
    </svg>
  );
}
