#pragma once
#include <sqlite3.h>
#include <stdio.h>
#include <iostream>
#include <string>

bool db_query_host(std::string host, std::string dbname);