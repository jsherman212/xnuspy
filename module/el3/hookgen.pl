#!/usr/bin/perl

open(DISFILE, "<xnuspy_el3_opcodes") or die("hookgen: fatal: couldn't open opcodes");

open(HEADER, ">$ARGV[0].h") or die("hookgen: fatal: couldn't open $ARGV[0].h");

printf(HEADER "#ifndef $ARGV[0]\n");
printf(HEADER "#define $ARGV[0]\n");

my $macroname = uc("WRITE_".$ARGV[0]);

printf(HEADER "#define $macroname \\\n");

my $num_instrs = 0;
my @function_starts;

while(my $line = <DISFILE>){
    chomp($line);

    my $cur_opcode = hex($line);

    # mov x18, x18
    if($cur_opcode == 0xaa1203f2){
        # +1 to get off of the mov x18, x18
        push(@function_starts, ($num_instrs+1)*4);
    }

    printf(HEADER "WRITE_LOADER_XFER_RECV_DATA_INSTR(%#x);", $cur_opcode);

    if(eof){
        printf(HEADER " \n");
    }
    else{
        printf(HEADER " \\\n");
    }

    $num_instrs += 1;
}

printf(HEADER "const static int g_$ARGV[0]_num_instrs = $num_instrs;\n");

my $function_starts_length = @function_starts;

if($function_starts_length > 0){
    # printf("@function_starts, $function_starts_length\n");
    printf(HEADER "const static unsigned int g_$ARGV[0]_function_starts[] = {\n");

    foreach my $function_start (@function_starts) {
        printf(HEADER "%#x,\n", $function_start);
    }

    printf(HEADER "};\n");
    printf(HEADER "const static int g_num_$ARGV[0]_function_starts = $function_starts_length;\n");
}

printf(HEADER "#endif\n");
