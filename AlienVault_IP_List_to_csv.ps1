## This script takes the ip addresses listed in the "input_ip_addresses.csv" file and scans them against the AlienVault OTX pulses and returns the results in csv format

# Define the input and output file paths using the present working directory
$inputCsvPath = Join-Path -Path (Get-Location) -ChildPath "input_ip_addresses.csv"
$outputCsvPath = Join-Path -Path (Get-Location) -ChildPath "OTX_List_scan_results.csv"

# Print debug information
Write-Output "Input CSV Path: $inputCsvPath"
Write-Output "Output CSV Path: $outputCsvPath"

# Define the AlienVault OTX API key and base URL
$apiKey = "[INSERT API KEY HERE]"
$baseUrl = "https://otx.alienvault.com/api/v1/indicators/IPv4/"

# Import the list of IP addresses from the input CSV
try {
    $ipAddresses = Import-Csv -Path $inputCsvPath
    Write-Output "Successfully imported IP addresses from CSV."
} catch {
    Write-Error "Failed to import IP addresses from CSV. Error: $_"
    exit
}

# Initialize an array to hold the results
$results = @()

# Iterate over each IP address and query the AlienVault OTX API
foreach ($ip in $ipAddresses) {
    $ipAddress = $ip.IP
    $apiUrl = "$baseUrl$ipAddress/general"
    
    # Make the API request
    try {
        Write-Output "Querying API for IP: $ipAddress"
        $response = Invoke-RestMethod -Uri $apiUrl -Headers @{ "X-OTX-API-KEY" = $apiKey }
        
        # Extract relevant data from the response
        $pulseInfo = $response.pulse_info.pulses | ForEach-Object {
            @{
                PulseID = $_.id
                PulseName = $_.name
                Description = $_.description
                Modified = $_.modified
                Created = $_.created
                Tags = ($_.tags -join "; ")
                TLP = $_.TLP
                Adversary = $_.adversary
                TargetedCountries = ($_.targeted_countries -join "; ")
                AttackIDs = ($_.attack_ids | ForEach-Object { $_.display_name }) -join "; "
                Industries = ($_.industries -join "; ")
            }
        }

        foreach ($pulse in $pulseInfo) {
            $results += [PSCustomObject]@{
                IPAddress = $response.indicator
                Reputation = $response.reputation
                Country = $response.country
                City = $response.city
                PulseID = $pulse.PulseID
                PulseName = $pulse.PulseName
                Description = $pulse.Description
                Modified = $pulse.Modified
                Created = $pulse.Created
                Tags = $pulse.Tags
                TLP = $pulse.TLP
                Adversary = $pulse.Adversary
                TargetedCountries = $pulse.TargetedCountries
                AttackIDs = $pulse.AttackIDs
                Industries = $pulse.Industries
            }
        }
        
    } catch {
        Write-Warning "Failed to get data for IP: $ipAddress. Error: $_"
        $results += [PSCustomObject]@{
            IPAddress = $ipAddress
            Reputation = "N/A"
            Country = "N/A"
            City = "N/A"
            PulseID = "N/A"
            PulseName = "N/A"
            Description = "N/A"
            Modified = "N/A"
            Created = "N/A"
            Tags = "N/A"
            TLP = "N/A"
            Adversary = "N/A"
            TargetedCountries = "N/A"
            AttackIDs = "N/A"
            Industries = "N/A"
        }
    }
}

# Export the results to the output CSV
try {
    $results | Export-Csv -Path $outputCsvPath -NoTypeInformation
    Write-Output "Scan complete. Results saved to $outputCsvPath"
} catch {
    Write-Error "Failed to save results to CSV. Error: $_"
}
