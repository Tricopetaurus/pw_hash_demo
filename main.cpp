#include <iostream>
#include <string>
#include <chrono>
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"

// Forward declaration of increment_combination
bool increment_combination(std::string& combination);

std::string sha256(const std::string str) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource s(str, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            ) // HexEncoder
        ) // HashFilter
    ); // StringSource

    return digest;
}

// Function to generate all combinations of lowercase letters, uppercase letters, and numbers
void generate_combinations(std::string hashed_password) {
    // Start with a single lowercase letter
    std::string combination = "a";

    // Initialize a counter for the number of attempts
    int attempts = 0;

    // Get the start time
    auto start = std::chrono::high_resolution_clock::now();

    do {
        // Increment the number of attempts
        attempts++;

        // If the current combination matches the password, print a success message and exit
        if (sha256(combination) == hashed_password) {
            // Get the end time
            auto end = std::chrono::high_resolution_clock::now();

            // Calculate and print the time taken
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
            std::cout << "Time taken: " << duration.count() << " seconds\n";

            // Print the number of attempts
            std::cout << "Attempts: " << attempts << "\n";

            std::cout << "Password cracked! It was '" << combination << "'.\n";
            return;
        }
    } while (increment_combination(combination));

    // If no match is found after trying all combinations, print a failure message
    std::cout << "Password not found through brute force.\n";
}

bool increment_combination(std::string& combination) {
    for (int i = combination.length() - 1; i >= 0; --i) {
        if (combination[i] < 'z') {
            ++combination[i];
            return true;
        }
        else {
            combination[i] = 'a';
        }
    }
    // If all characters are 'z', add another character
    combination.push_back('a');
    return true;
}

int main() {
    // Declare a string to hold the hashed password
    std::string hashed_password;

    while (true) {
        // Prompt the user to enter a hashed password
        std::cout << "Enter a hashed password: ";

        // Read the hashed password from user input
        std::cin >> hashed_password;

        // Generate and test combinations of lowercase letters, uppercase letters, and numbers
        generate_combinations(hashed_password);
    }

    return 0;
}
