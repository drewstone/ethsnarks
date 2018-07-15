#include <stdio.h>

#include "miximus.hpp"

int main( int argc, char **argv )
{
	if( argc < 3 )
	{
		fprintf(stderr, "Usage: %s <pk-output.json> <vk-output.json>\n", argv[0]);
		return 1;
	}

	genKeys(argv[1], argv[2]);
	return 0;
}
