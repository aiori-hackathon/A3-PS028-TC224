import React from 'react';
import { SCENARIO_METADATA, ALL_SCENARIOS } from '@/lib/analytics/analytics-filters';
import { Layers } from 'lucide-react';

interface ScenarioSelectorProps {
  selectedScenarios: string[];
  onChange: (scenarios: string[]) => void;
  trialCountsByScenario: Record<string, number>;
}

export const ScenarioSelector: React.FC<ScenarioSelectorProps> = ({
  selectedScenarios,
  onChange,
  trialCountsByScenario,
}) => {
  const toggleScenario = (id: string) => {
    if (selectedScenarios.includes(id)) {
      onChange(selectedScenarios.filter((s) => s !== id));
    } else {
      onChange([...selectedScenarios, id].sort());
    }
  };

  const selectAll = () => {
    onChange([...ALL_SCENARIOS]);
  };

  const clearAll = () => {
    onChange([]);
  };

  const allSelected = selectedScenarios.length === ALL_SCENARIOS.length;
  const noneSelected = selectedScenarios.length === 0;

  return (
    <div data-testid="scenario-selector" className="rounded-lg border bg-card p-4 space-y-3 shadow-xs">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-2.5">
        <div className="flex items-center gap-2">
          <Layers className="size-4 text-primary" />
          <h3 className="font-semibold text-sm sm:text-base">Scenario Selection</h3>
          <span className="text-xs text-muted-foreground ml-1">
            ({selectedScenarios.length} of {ALL_SCENARIOS.length} selected)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid="select-all-btn"
            onClick={selectAll}
            disabled={allSelected}
            className="px-2.5 py-1 text-xs rounded font-medium border bg-background hover:bg-primary hover:text-primary-foreground disabled:opacity-40 transition-colors cursor-pointer"
          >
            Select All
          </button>
          <button
            type="button"
            data-testid="clear-all-btn"
            onClick={clearAll}
            disabled={noneSelected}
            className="px-2.5 py-1 text-xs rounded font-medium border bg-background hover:bg-destructive hover:text-white disabled:opacity-40 transition-colors cursor-pointer"
          >
            Clear Selection
          </button>
        </div>
      </div>

      {/* Grid of Scenario Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
        {ALL_SCENARIOS.map((id) => {
          const meta = SCENARIO_METADATA[id]!;
          const isSelected = selectedScenarios.includes(id);
          const count = trialCountsByScenario[id] ?? 0;

          return (
            <button
              key={id}
              type="button"
              data-testid={`scenario-card-${id}`}
              onClick={() => toggleScenario(id)}
              aria-pressed={isSelected}
              className={`text-left p-2.5 rounded-lg border transition-all cursor-pointer flex flex-col justify-between ${
                isSelected
                  ? 'border-primary bg-primary/10 shadow-xs ring-1 ring-primary/40'
                  : 'border-border/60 bg-background/60 hover:bg-muted/40 hover:border-border opacity-75'
              }`}
            >
              <div className="flex items-center justify-between gap-1 w-full mb-1">
                <span className="font-bold text-sm tracking-tight text-foreground flex items-center gap-1.5">
                  <span
                    className={`size-2 rounded-full ${
                      isSelected ? 'bg-primary' : 'bg-muted-foreground/40'
                    }`}
                  />
                  {id}
                </span>
                <span
                  className={`text-[11px] px-1.5 py-0.2 rounded font-mono ${
                    isSelected
                      ? 'bg-primary text-primary-foreground font-semibold'
                      : 'bg-muted text-muted-foreground'
                  }`}
                >
                  n={count}
                </span>
              </div>

              <div className="text-xs font-medium text-foreground line-clamp-1 leading-snug">
                {meta.name}
              </div>

              <div className="text-[11px] text-muted-foreground line-clamp-2 mt-1 leading-tight">
                {meta.description}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
