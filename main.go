package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/audi70r/diligent/db"
)

const (
	maxFollowups        = 5    // Maximum number of follow-up analyses
	maxOutputCharacters = 3000 // Maximum number of characters from command output to send to OpenAI
)

// Check represents a single command check.
type Check struct {
	Command string `json:"command"`
	Prompt  string `json:"prompt"`
}

// OSChecks holds lists of checks for different operating systems.
type OSChecks struct {
	MacOS   []Check `json:"macOS"`
	Windows []Check `json:"windows"`
	Linux   []Check `json:"linux"`
}

// GPTResponse is the structured JSON response expected from the OpenAI API.
type GPTResponse struct {
	Flagged         bool   `json:"flagged"`
	Description     string `json:"description"`
	FollowUpPrompt  string `json:"follow_up_prompt,omitempty"`
	FollowUpCommand string `json:"follow_up_command,omitempty"`
	Alert           string `json:"alert,omitempty"`
}

// AnalysisItem holds all information about one analysis step (initial or follow-up).
type AnalysisItem struct {
	Prompt              string         `json:"prompt,omitempty"`
	Command             string         `json:"command,omitempty"`
	Flagged             bool           `json:"flagged"`
	AnalysisDescription string         `json:"analysis_description,omitempty"`
	Alert               string         `json:"alert,omitempty"`
	RawOutput           string         `json:"raw_output,omitempty"`
	FollowUps           []AnalysisItem `json:"follow_ups,omitempty"`
}

type Report struct {
	Items []AnalysisItem `json:"items"`
}

var checks = OSChecks{
	MacOS: []Check{
		{Command: "system_profiler SPUSBDataType -json", Prompt: "Look for any suspicious USB devices."},
		{Command: "ps -Ao user,pid,%cpu,%mem,comm", Prompt: "Analyze processes for unusual CPU or memory usage."},
		{Command: "netstat -an", Prompt: "Identify suspicious or unusual network connections."},
		{Command: "last", Prompt: "Review login history for any unusual user activity."},
		{Command: "dscl . list /Users", Prompt: "Check for unexpected or unauthorized user accounts."},
		{Command: "pmset -g log | grep -i failure", Prompt: "Check for power management failures or unexpected events."},
		{Command: "sudo dmesg | tail -n 50", Prompt: "Analyze recent kernel messages for potential issues."},
		{Command: "ls /Users/Shared", Prompt: "Check for suspicious files in the shared user directory."},
		{Command: "launchctl list", Prompt: "Check running services/daemons for suspicious entries."},
		{Command: "crontab -l", Prompt: "Check for suspicious cron jobs."},
		{Command: "sudo fdesetup status", Prompt: "Check if FileVault disk encryption is enabled or disabled."},
		{Command: "kextstat", Prompt: "Examine loaded kernel extensions for anything unusual."},
		{Command: "sudo launchctl list | grep -v com.apple", Prompt: "Check for non-Apple launch services that might be malicious."},
		{Command: "sudo defaults read /Library/Preferences/com.apple.loginwindow", Prompt: "Inspect login window preferences for suspicious settings."},
		{Command: "mdutil -s /", Prompt: "Check Spotlight indexing status; unexpected changes could indicate tampering."},
		{Command: "sudo lsof -i", Prompt: "Review open files and network connections for suspicious activity."},
		{Command: "sudo ls -la /etc/sudoers.d", Prompt: "Check for unauthorized sudoers modifications."},
		{Command: "cat /etc/hosts", Prompt: "Look for malicious modifications to the hosts file."},
		{Command: "sudo tmutil listbackups", Prompt: "Check Time Machine backups for irregularities or suspicious modifications."},
		{Command: "security find-generic-password -ga test 2>&1", Prompt: "Inspect keychain items for suspicious credentials."},
		{Command: "sudo spctl --status", Prompt: "Check Gatekeeper status for unexpected configuration."},
		{Command: "ioreg -l", Prompt: "Inspect hardware registry for suspicious devices or properties."},
	},
}

// callOpenAI sends a prompt to the OpenAI ChatCompletion API and returns a GPTResponse.
func callOpenAI(client *openai.Client, prompt string) (GPTResponse, error) {
	systemMessage := `You are a careful and accurate system analyst. 
Your task is to evaluate the provided command output in the context of the given prompt and determine if there is any truly suspicious activity.
Return data as JSON:
{
  "flagged": boolean,
  "description": string,
  "follow_up_prompt": string,
  "follow_up_command": string,
  "alert": string
}
Do not include any extra text outside of the JSON object.`

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		MaxTokens: 8100,
		Model:     openai.GPT4oMini20240718,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: systemMessage,
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
	})
	if err != nil {
		return GPTResponse{}, err
	}

	var gptResp GPTResponse
	err = json.Unmarshal([]byte(resp.Choices[0].Message.Content), &gptResp)
	if err != nil {
		return GPTResponse{}, fmt.Errorf("failed to parse GPT response: %w", err)
	}

	return gptResp, nil
}

// executeCommand runs a shell command and returns its combined output.
func executeCommand(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute command: %s, error: %w", command, err)
	}
	return string(output), nil
}

// truncateOutput truncates the output to a maximum number of characters.
func truncateOutput(output string, maxLen int) string {
	if len(output) > maxLen {
		return output[:maxLen]
	}
	return output
}

// analyze handles the analysis of a command and any follow-ups it generates.
func analyze(client *openai.Client, prompt, command string, depth int) (AnalysisItem, error) {
	item := AnalysisItem{
		Prompt:  prompt,
		Command: command,
	}

	// If no command, just analyze the prompt directly
	if command == "" {
		response, err := callOpenAI(client, prompt)
		if err != nil {
			item.Flagged = false
			item.AnalysisDescription = fmt.Sprintf("OpenAI API error: %v", err)
			return item, nil
		}
		item.Flagged = response.Flagged
		item.AnalysisDescription = response.Description
		item.Alert = response.Alert
		return item, nil
	}

	fmt.Printf("%sExecuting command: %s\n", indent(depth), command)
	commandOutput, err := executeCommand(command)
	if err != nil {
		item.Flagged = false
		item.AnalysisDescription = fmt.Sprintf("Command execution error: %v", err)
		item.RawOutput = commandOutput
		return item, nil
	}

	// Truncate and prepare for analysis
	truncatedOutput := truncateOutput(commandOutput, maxOutputCharacters)
	fullPrompt := fmt.Sprintf("%s\n\nCommand output (truncated if necessary):\n%s", prompt, truncatedOutput)

	// Analyze with OpenAI
	response, err := callOpenAI(client, fullPrompt)
	if err != nil {
		item.Flagged = false
		item.AnalysisDescription = fmt.Sprintf("OpenAI API error: %v", err)
		item.RawOutput = truncatedOutput
		return item, nil
	}

	// Set item fields from response
	item.Flagged = response.Flagged
	item.AnalysisDescription = response.Description
	item.Alert = response.Alert
	item.RawOutput = truncatedOutput

	// Handle multiple follow-ups if suggested
	currentResponse := response
	currentDepth := depth
	for item.Flagged && currentResponse.FollowUpCommand != "" && currentResponse.FollowUpPrompt != "" && currentDepth < maxFollowups {
		currentDepth++
		fmt.Printf("%sExecuting follow-up command: %s\n", indent(currentDepth), currentResponse.FollowUpCommand)
		followupItem, err := analyze(client, currentResponse.FollowUpPrompt, currentResponse.FollowUpCommand, currentDepth)
		if err != nil {
			// If follow-up fails, break out
			break
		}
		// Append the follow-up result
		item.FollowUps = append(item.FollowUps, followupItem)

		// Update the main item's state based on the follow-up result
		//item.Flagged = followupItem.Flagged // TODO: Decide how to handle this
		item.AnalysisDescription = followupItem.AnalysisDescription
		item.Alert = followupItem.Alert

		// If the follow-up item is flagged and suggests another follow-up, continue
		if len(followupItem.FollowUps) > 0 {
			// If that follow-up had further follow-ups, they are already included in followupItem.FollowUps
			// We break here since analyze() recursively handled deeper follow-ups.
			break
		}

		// Otherwise, if this follow-up also suggests another follow-up, re-analyze with its response
		// Since `followupItem` is a fully analyzed item, if it had a next follow-up suggestion,
		// it would have been handled already in recursion. So we don't need to continue a loop here.
		// If you want to handle chaining multiple follow-ups at the same level, you'd need the GPTResponse again here.
		// In this scenario, analyze returns a fully processed item including nested follow-ups.
		// So there's no need to loop again at this level.
		break
	}

	return item, nil
}

// indent returns a string of spaces for pretty-printing at given depth.
func indent(depth int) string {
	return strings.Repeat("  ", depth)
}

func main() {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		fmt.Println("OpenAI API key is not set")
		return
	}

	err := db.InitDB()
	if err != nil {
		fmt.Printf("Error initializing database: %v\n", err)
		return
	}

	client := openai.NewClient(apiKey)

	// Analyze each check and store results
	results := make([]AnalysisItem, 0, len(checks.MacOS))
	for _, chk := range checks.MacOS {
		item, err := analyze(client, chk.Prompt, chk.Command, 0)
		if err != nil {
			fmt.Printf("Error analyzing command %s: %v\n", chk.Command, err)
			continue
		}
		results = append(results, item)
	}

	report := Report{Items: results}

	reportString, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling report: %v\n", err)
	}

	db.CreateLog(time.Now(), string(reportString))
}
