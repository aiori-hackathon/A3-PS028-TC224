import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group.tsx";
import React, { useState } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";
import { getDeviceInfo } from "@/lib/device-info.ts";
import { sleep } from "@/lib/test-utils.ts";
import { Spinner } from "@/components/ui/spinner.tsx";
import { WandSparklesIcon } from "lucide-react";

export const DeviceInfoInput: React.FC<{
  deviceInfo: string;
  setDeviceInfo: (deviceInfo: string) => void;
  disabled: boolean;
}> = ({ deviceInfo, setDeviceInfo, disabled }) => {
  return (
    <InputGroup className="max-w-xl">
      <InputGroupInput
        type="text"
        placeholder="OS, device, browser, your name, etc."
        value={deviceInfo}
        onChange={(e) => setDeviceInfo(e.target.value)}
        disabled={disabled}
        className="text-sm"
      />
      <InputGroupAddon align="inline-end">
        <AutofillButton disabled={disabled} setDeviceInfo={setDeviceInfo} />
      </InputGroupAddon>
    </InputGroup>
  );
};

const AutofillButton: React.FC<{
  disabled: boolean;
  setDeviceInfo: (deviceInfo: string) => void;
}> = ({ disabled, setDeviceInfo }) => {
  const [isLoading, setIsLoading] = useState(false);

  const autofill = async () => {
    try {
      setIsLoading(true);

      const info = await getDeviceInfo();
      await sleep(100);

      if (!disabled) {
        setDeviceInfo(info);
      }
    } catch (err) {
      alert(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild={true}>
        <InputGroupButton
          variant="secondary"
          disabled={disabled || isLoading}
          onClick={autofill}
          className="text-sm"
        >
          {isLoading ? <Spinner /> : <WandSparklesIcon />}
          Autofill
        </InputGroupButton>
      </TooltipTrigger>
      <TooltipContent>
        Automatically detect device information.
        <br />
        Please update the auto-filled data if incorrect!
      </TooltipContent>
    </Tooltip>
  );
};
