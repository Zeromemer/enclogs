#include "include/input.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

static char *line_read = (char *)NULL;

void init_rl() {
	rl_bind_key('\t', rl_insert);
}

char *rl_gets(const char *prompt)
{
  /* If the buffer has already been allocated,
	 return the memory to the free pool. */
	if (line_read)
	{
		free (line_read);
		line_read = (char *)NULL;
	}

	/* Get a line from the user. */
	line_read = readline (prompt);

	/* If the line has any text in it,
		save it on the history. */
	if (line_read && *line_read)
		add_history (line_read);

	return (line_read);
}

char *rl_getps(const char *prompt) {
	struct termios old, new;
	
	tcgetattr(STDIN_FILENO, &old);
	new = old;
	new.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	char *passwd = rl_gets(prompt);

	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	printf("\n");

	return passwd;
}