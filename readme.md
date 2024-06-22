# Knapsack Problem Solver

This Python program implements a solution to the Knapsack Problem, which is a classic optimization problem in computer science and mathematics. The Knapsack Problem involves selecting a subset of items with varying weights and values, such that the total weight does not exceed a given capacity, while maximizing the total value of the selected items.

## Description

The Knapsack Problem can be stated as follows: Given a set of items, each with a weight and a value, determine the items to include in a collection so that the total weight is less than or equal to a given limit and the total value is as large as possible.

This program provides a solution to the Knapsack Problem using a dynamic programming approach. It takes a set of items with their respective weights and values, along with the maximum capacity of the knapsack, and returns the optimal subset of items that maximizes the total value while staying within the weight limit.

## Usage




knapsack.py [OPTIONS] [ITEMS]

Options: -c, --capacity INTEGER Maximum capacity of the knapsack. --version Show the version and exit. --help Show this message and exit.


To use the program, follow these steps:

1. Provide the list of items as command-line arguments in the format `weight:value`. For example:




knapsack.py 5:10 4:8 3:6 2:4 --capacity 10


This represents four items with weights 5, 4, 3, and 2, and values 10, 8, 6, and 4, respectively. The maximum capacity of the knapsack is set to 10.

2. The program will output the optimal subset of items that maximizes the total value while staying within the weight limit.

## Notes

- The program assumes that the input items are provided in the correct format (`weight:value`).
- If no items are provided, the program will exit with an error.
- If the `--capacity` option is not provided, the program will prompt the user to enter the maximum capacity.
- The program uses a dynamic programming approach to solve the Knapsack Problem efficiently.

## Dependencies

- [click](https://click.palletsprojects.com/en/8.1.x/) (for command-line interface)