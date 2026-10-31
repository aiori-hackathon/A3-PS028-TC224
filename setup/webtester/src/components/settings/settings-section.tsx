import React from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select.tsx";
import { Checkbox } from "@/components/ui/checkbox.tsx";
import { Button } from "@/components/ui/button.tsx";
import {
  HTTPSRecord,
  IPDelayType,
  IPVersion,
  Protocol,
  type TestSettings,
} from "@/lib/test-run.ts";
import { Input } from "@/components/ui/input.tsx";
import { DeviceInfoInput } from "@/components/settings/device-info-input.tsx";
import {
  SettingsDivider,
  SettingsItem,
} from "@/components/settings/settings-item";
import type { EnabledTestSettings } from "@/lib/settings.ts";
import { DelayRangeInput } from "@/components/settings/delay-range-input.tsx";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";

type Props = {
  enabledSettings: EnabledTestSettings;
  settings: TestSettings;
  setSettings: (settings: TestSettings) => void;
  runTest: () => void;
  downloadTestConfiguration: () => void;
  showDividers?: boolean;
  disabled?: boolean;
  disableProtocolHandshakeDelayRangeSetting?: boolean;
};

export const SettingsSection: React.FC<Props> = ({
  enabledSettings,
  settings,
  setSettings,
  runTest,
  downloadTestConfiguration,
  showDividers = false,
  disabled = false,
  disableProtocolHandshakeDelayRangeSetting = false,
}) => {
  return (
    <div>
      <div className="grid gap-y-7 md:gap-y-3">
        {enabledSettings.repetitions !== undefined && (
          <SettingsItem label="Repetitions">
            <Select
              value={settings.repetitions.toString()}
              onValueChange={(value) =>
                setSettings({ ...settings, repetitions: Number(value) })
              }
              disabled={disabled}
            >
              <SelectTrigger className="w-full max-w-30">
                <SelectValue>{settings.repetitions}</SelectValue>
              </SelectTrigger>
              <SelectContent align="start">
                {enabledSettings.repetitions.options.map((value) => (
                  <SelectItem value={value.toString()} key={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsItem>
        )}

        {enabledSettings.httpsRecord !== undefined && (
          <SettingsItem
            label="HTTPS RR"
            helpText={
              "Our DNS server configures an HTTPS resource record for each test domain " +
              "so clients can discover HTTP/3 availability. You can customize the HTTPS " +
              "record values for advanced test cases."
            }
          >
            <Select
              value={settings.httpsRecord}
              onValueChange={(value) =>
                setSettings({ ...settings, httpsRecord: value as HTTPSRecord })
              }
              disabled={disabled}
            >
              <SelectTrigger className="w-full max-w-60">
                <SelectValue>{settings.httpsRecord}</SelectValue>
              </SelectTrigger>
              <SelectContent align="start">
                {enabledSettings.httpsRecord.options.map((value) => (
                  <SelectItem value={value} key={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsItem>
        )}

        {showDividers && <SettingsDivider />}

        {enabledSettings.ipDelayType !== undefined && (
          <SettingsItem
            label="IP delay type"
            helpText={
              <div className="space-y-2">
                <p>
                  The test environment offers two methods for introducing IPv4
                  or IPv6 delays:
                </p>
                <ul className="space-y-2">
                  <li>
                    <b>Network Latency</b>: The server simulates network latency
                    by delaying every incoming IP packet. This is implemented
                    using tc netem, which assigns a specific delay to each of
                    the server's individual IP addresses. Please note two
                    limitations of this setup: First, because the server has a
                    limited number of IP addresses, only a limited number of
                    distinct delays can be configured. Second, due to the
                    current server configuration, this method only supports
                    delaying IPv6 packets (though this is typically the desired
                    testing behavior).
                  </li>
                  <li>
                    <b>Handshake Delay</b>: The test environment can also
                    introduce delays once during the transport or application
                    layer handshake, similar to the how QUIC and TLS delays are
                    introduced. While this feature offers the flexibility to
                    test an arbitrary range of delays, it might not trigger the
                    expected behavior in all clients. This is because some
                    clients do not use the transport/application layer handshake
                    as a signal for a successful connection attempt, as defined
                    by the Happy Eyeballs version 3 standard.
                  </li>
                </ul>
              </div>
            }
          >
            <Select
              value={settings.ipDelayType}
              onValueChange={(value) =>
                setSettings({
                  ...settings,
                  ipDelayType: value as IPDelayType,
                })
              }
              disabled={disabled}
            >
              <SelectTrigger className="w-full max-w-120">
                <SelectValue>{settings.ipDelayType}</SelectValue>
              </SelectTrigger>
              <SelectContent align="start">
                {enabledSettings.ipDelayType.options.map((value) => (
                  <SelectItem value={value} key={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsItem>
        )}

        {enabledSettings.delayedIPVersion !== undefined && (
          <SettingsItem label="Delayed IP version">
            <Select
              value={settings.delayedIPVersion}
              onValueChange={(value) =>
                setSettings({
                  ...settings,
                  delayedIPVersion: value as IPVersion,
                })
              }
              disabled={disabled}
            >
              <SelectTrigger className="w-full max-w-30">
                <SelectValue>{settings.delayedIPVersion}</SelectValue>
              </SelectTrigger>
              <SelectContent align="start">
                {enabledSettings.delayedIPVersion.options.map((value) => (
                  <SelectItem value={value} key={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsItem>
        )}

        {enabledSettings.ipHandshakeDelayRange !== undefined && (
          <SettingsItem label="IP delays">
            <DelayRangeInput
              delayRange={settings.ipHandshakeDelayRange}
              setDelayRange={(delayRange) =>
                setSettings({
                  ...settings,
                  ipHandshakeDelayRange: delayRange,
                })
              }
              disabled={disabled}
            />
          </SettingsItem>
        )}

        {showDividers && <SettingsDivider />}

        {enabledSettings.delayedProtocol !== undefined && (
          <SettingsItem
            label="Delayed protocol"
            helpText="The delay is applied once to the first packet of the QUIC or TLS handshake."
          >
            <Select
              value={settings.delayedProtocol}
              onValueChange={(value) =>
                setSettings({ ...settings, delayedProtocol: value as Protocol })
              }
              disabled={disabled}
            >
              <SelectTrigger className="w-full max-w-30">
                <SelectValue>{settings.delayedProtocol}</SelectValue>
              </SelectTrigger>
              <SelectContent align="start">
                {enabledSettings.delayedProtocol.options.map((value) => (
                  <SelectItem value={value} key={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsItem>
        )}

        {enabledSettings.protocolHandshakeDelayRange !== undefined && (
          <SettingsItem label="Protocol handshake delays">
            <DelayRangeInput
              delayRange={settings.protocolHandshakeDelayRange}
              setDelayRange={(delayRange) =>
                setSettings({
                  ...settings,
                  protocolHandshakeDelayRange: delayRange,
                })
              }
              disabled={disabled || disableProtocolHandshakeDelayRangeSetting}
            />
          </SettingsItem>
        )}

        {showDividers && <SettingsDivider />}

        {enabledSettings.randomizeDomains !== undefined && (
          <SettingsItem
            label="Randomize domains"
            helpText={
              "When enabled, the a randomized segment is added to the test domain. " +
              "This prevents DNS caching, ensuring that individual tests do not " +
              "interfere with or skew each other's results."
            }
          >
            <Checkbox
              checked={settings.randomizeDomains}
              onCheckedChange={(checked) =>
                setSettings({ ...settings, randomizeDomains: !!checked })
              }
              disabled={disabled}
            />
          </SettingsItem>
        )}

        {enabledSettings.autoTransmitResults !== undefined && (
          <SettingsItem
            label="Automatically transmit results"
            helpText={
              <div className="space-y-2">
                <p>
                  By default, measurement results are not transmitted
                  automatically. If you wish to contribute to our analysis, you
                  can enable this setting to transmit your test results
                  automatically after the run completes. Alternatively, you can
                  manually submit your results using the button at the bottom of
                  the page.
                </p>
                <p>
                  If you choose to transmit your results, the web-tester
                  transmits the measurement data along with your user agent and
                  browser vendor information. We do not collect or store your IP
                  address. To help us better interpret the test results, you can
                  optionally provide details about your network environment in
                  the device and user information field.
                </p>
              </div>
            }
          >
            <Checkbox
              checked={settings.autoTransmitResults}
              onCheckedChange={(checked) =>
                setSettings({ ...settings, autoTransmitResults: !!checked })
              }
              disabled={disabled}
            />
          </SettingsItem>
        )}

        {enabledSettings.resolverAddresses !== undefined && (
          <SettingsItem
            label="Configured resolver IP addresses (optional)"
            helpText={
              "Specifying the client's configured DNS resolver IP addresses assists in " +
              "interpreting transmitted results. This data is attached solely as " +
              "metadata to transmitted results and does not affect the test execution."
            }
          >
            <Input
              type="text"
              placeholder="e.g., 8.8.8.8, 8.8.4.4"
              value={settings.resolverAddresses}
              onChange={(e) =>
                setSettings({ ...settings, resolverAddresses: e.target.value })
              }
              disabled={disabled}
              className="max-w-xl"
            />
          </SettingsItem>
        )}

        {enabledSettings.deviceInfo !== undefined && (
          <SettingsItem
            label="Device and user information (optional)"
            helpText={
              "To help us better interpret transmitted test results, you can optionally provide " +
              "details about your network environment in this field. This data is " +
              "attached solely as metadata to transmitted results and does not affect the test execution."
            }
          >
            <DeviceInfoInput
              deviceInfo={settings.deviceInfo}
              setDeviceInfo={(deviceInfo) =>
                setSettings({ ...settings, deviceInfo })
              }
              disabled={disabled}
            />
          </SettingsItem>
        )}
      </div>

      <div className="mt-8 flex gap-x-4 gap-y-2 items-center flex-wrap">
        <Button disabled={disabled} onClick={runTest}>
          Run test
        </Button>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="secondary"
              disabled={disabled}
              onClick={downloadTestConfiguration}
            >
              Download test configuration
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Download generated test domains and corresponding delay
            configurations and metadata for dedicated testing.
          </TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
};
