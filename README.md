# GPT-Based Security Scanner

This program is a cross-platform security scanner that performs system checks for potential anomalies, suspicious activity, or malicious behavior. It utilizes a combination of pre-defined shell commands and the OpenAI GPT API to analyze command outputs, flag issues, and provide follow-up actions. The program is designed to work on macOS, Linux, and Windows, but this version includes commands specifically for macOS.

## Features

- **Automated System Analysis**: Executes pre-defined shell commands to gather system information and identify potential security threats.
- **GPT-Powered Analysis**: Leverages the OpenAI GPT API to analyze command outputs, detect anomalies, and provide detailed descriptions of flagged issues.
- **Follow-Up Actions**: Suggests and executes follow-up commands for deeper analysis of flagged issues.
- **Customizable Commands**: Easily add or modify checks for different operating systems.
- **Report Generation**: Saves the analysis results in a JSON file (`report.json`) and logs them in a database.
- **Cross-Platform Support**: Designed to support macOS, Linux, and Windows (currently populated with macOS-specific commands).

## How It Works

1. **Initialization**:
    - Detects the operating system.
    - Initializes the database for logging reports.

2. **Execution**:
    - Runs a series of shell commands based on the detected OS.
    - Captures and truncates the command output (if necessary).

3. **Analysis**:
    - Sends the command output and context to the OpenAI GPT API for analysis.
    - Receives a structured JSON response with:
        - Whether the issue is flagged.
        - A description of the issue.
        - Suggested follow-up prompts and commands (if applicable).
        - Alerts for critical issues.

4. **Follow-Up**:
    - Executes suggested follow-up commands and repeats the analysis process for a maximum of 5 levels.

5. **Report Generation**:
    - Aggregates all analysis results and follow-ups into a structured report.
    - Logs the report in a database and saves it to `report.json`.

## Prerequisites

- [OpenAI API Key](https://platform.openai.com/signup/): Set the API key as an environment variable `OPENAI_API_KEY`.
- Go 1.19 or later.
- Dependencies installed via `go mod tidy`.
- Database connection (configured in `db` package).

## Installation

1. Clone the repository:
   ```sh
   git clone <repository_url>
   cd <repository_directory>
   ```

2. Install dependencies:
   ```sh
   go mod tidy
   ```

3. Set up the database connection using the `db` package.

4. Set the OpenAI API key:
   ```sh
   export OPENAI_API_KEY=your_api_key_here
   ```

## Usage

1. Run the program:
   ```sh
   go run main.go
   ```

2. The program will:
    - Execute predefined checks for the detected operating system.
    - Analyze the outputs using OpenAI GPT.
    - Save the report to `report.json` and log it in the database.

3. Review the results:
    - Open `report.json` to view the detailed analysis report.
    - Check the database logs for historical data.

## Example Checks (macOS)

- **USB Devices**:
  Detect suspicious USB devices.
  ```sh
  system_profiler SPUSBDataType -json | jq '.SPUSBDataType[] | select(."_name" | test("keyboard|mouse|storage|hub"; "i"))'
  ```

- **Top Processes**:
  Analyze top processes for unusual CPU or memory usage.
  ```sh
  ps -Ao user,pid,%cpu,%mem,comm --sort=-%cpu | head -n 20
  ```

- **Network Connections**:
  Identify top suspicious or unusual network connections.
  ```sh
  netstat -an | grep -E 'ESTABLISHED|LISTEN' | awk '{print $4,$5,$6}' | uniq -c | sort -nr | head -n 20
  ```

- **Login History**:
  Review recent login history for unusual user activity.
  ```sh
  last | head -n 20
  ```

## Configuration

- Modify `OSChecks` in the source code to add or update checks for macOS, Linux, or Windows.
- Update `maxFollowups` or `maxOutputCharacters` constants to adjust the depth of follow-ups or output size.

## Known Limitations

- **macOS Focus**: The current implementation primarily includes macOS checks. Additional commands for Linux and Windows should be added for full cross-platform support.
- **Command Execution Risks**: Running commands may require elevated privileges and could impact system performance.
- **Rate Limits**: OpenAI API rate limits could affect performance for large-scale or frequent analysis.
- **JSON Parsing**: Incorrect or unexpected JSON responses from OpenAI might cause errors.

## Contributing

1. Fork the repository.
2. Create a feature branch:
   ```sh
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```sh
   git commit -m "Add feature name"
   ```
4. Push to the branch:
   ```sh
   git push origin feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

