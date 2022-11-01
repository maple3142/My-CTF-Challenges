#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

int main() {
	std::string name;
	bool premium = false;
	std::string s;
	std::string_view command = "ls";

	std::cout << "What's your name? ";
	std::cin >> name;

	int choice;
	while (1) {
		std::cout << "==== Menu ====" << std::endl;
		std::cout << "1. Change name" << std::endl;
		std::cout << "2. Status" << std::endl;
		std::cout << "3. Set command" << std::endl;
		std::cout << "4. Execute command" << std::endl;
		std::cout << "> ";
		std::cin >> choice;
		switch (choice) {
			case 1:
				std::cout << "What's your new name? ";
				std::cin >> name;
				break;
			case 2:
				std::cout << "==== Status ====" << std::endl;
				std::cout << "Username: "
				          << "@" + name << std::endl;
				std::cout << "Is premium: " << premium << std::endl;
				break;
			case 3:
				std::cin >> s;
				if (!premium) {
					command = "#" + s;
				}
				break;
			case 4:
				std::cout << "Executing " << command << std::endl;
				std::system(command.data());
				break;
			default:
				std::cout << "Invalid choice" << std::endl;
				exit(0);
		}
	}
	return 0;
}
// g++ main.cpp -Wall -g -o chall
