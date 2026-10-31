import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { CheckIcon, CopyIcon } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";
import { cn } from "@/lib/utils.ts";

export const CopyToClipboardButton: React.FC<{
  text: string;
  children?: React.ReactNode;
}> = ({ text, children }) => {
  const [hasCopied, setHasCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(text);

    setHasCopied(true);
    setTimeout(() => setHasCopied(false), 1000);
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild={true}>
        <Button onClick={copyToClipboard} size={children ? undefined : "icon"}>
          <div className="relative flex items-center justify-center size-4">
            <CopyIcon
              className={cn(
                "absolute size-4 transition-all duration-300",
                hasCopied ? "scale-0 opacity-0" : "scale-100 opacity-100",
              )}
            />

            <CheckIcon
              className={cn(
                "absolute size-4 transition-all duration-300",
                hasCopied ? "scale-100 opacity-100" : "scale-0 opacity-0",
              )}
            />
          </div>

          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        {hasCopied ? "Copied!" : "Copy to clipboard"}
      </TooltipContent>
    </Tooltip>
  );
};
