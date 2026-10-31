import React, { useState } from "react";
import { CircleHelpIcon } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";

export const SettingsItem: React.FC<{
  label: string;
  helpText?: React.ReactNode;
  children?: React.ReactNode;
}> = ({ label, helpText, children }) => {
  const [isTooltipOpen, setTooltipOpen] = useState(false);

  return (
    <div className="grid md:grid-cols-[230px_1fr] md:gap-x-10 gap-y-2 items-center min-h-8">
      <div className="text-sm leading-snug">
        <div className="inline mr-2">{label}</div>

        {helpText && (
          <Tooltip open={isTooltipOpen} onOpenChange={setTooltipOpen}>
            <TooltipTrigger asChild={true}>
              <CircleHelpIcon
                className="size-4.5 inline align-text-bottom text-blue-400"
                onClick={(event) => {
                  event.preventDefault();
                  setTooltipOpen((open) => !open);
                }}
              />
            </TooltipTrigger>
            <TooltipContent className="text-sm md:max-w-3xl">
              {helpText}
            </TooltipContent>
          </Tooltip>
        )}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
};

export const SettingsDivider: React.FC = () => (
  <div className="border-t my-4" />
);
