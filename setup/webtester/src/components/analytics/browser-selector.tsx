import React from 'react';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';
import { BROWSER_OPTIONS } from '@/lib/analytics/analytics-filters';
import { Globe } from 'lucide-react';

interface BrowserSelectorProps {
  selectedBrowser: BrowserFilterId;
  onChange: (browser: BrowserFilterId) => void;
}

export const BrowserSelector: React.FC<BrowserSelectorProps> = ({
  selectedBrowser,
  onChange,
}) => {
  return (
    <div className="flex items-center gap-1.5 bg-background p-1 rounded-lg border text-xs sm:text-sm">
      <div className="flex items-center gap-1 px-2 text-muted-foreground font-medium">
        <Globe className="size-3.5" />
        <span className="hidden sm:inline">Browser:</span>
      </div>
      <div className="flex items-center gap-1">
        {BROWSER_OPTIONS.map((opt) => {
          const isSelected = selectedBrowser === opt.id;
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => onChange(opt.id)}
              aria-pressed={isSelected}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                isSelected
                  ? 'bg-primary text-primary-foreground shadow-xs font-semibold'
                  : 'text-foreground hover:bg-muted/60'
              }`}
            >
              {opt.shortLabel}
            </button>
          );
        })}
      </div>
    </div>
  );
};
