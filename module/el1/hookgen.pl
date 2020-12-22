#!/usr/bin/perl

system("clang -O0 -arch arm64 -isysroot \$(xcrun --sdk iphoneos --show-sdk-path) $ARGV[0].s -o $ARGV[0]");

if(system("../../opdump/opdump $ARGV[0] ./dis") != 0){
    die("hookgen: fatal: opdump failed\n");
}

open(DISFILE, "<dis") or die("hookgen: fatal: couldn't open dis file");

open(HEADER, ">$ARGV[0]_instrs.h") or die("hookgen: fatal: couldn't open $ARGV[0]_instrs.h");

printf(HEADER "#ifndef $ARGV[0]_instrs\n");
printf(HEADER "#define $ARGV[0]_instrs\n");

my $macroname = uc("WRITE_".$ARGV[0]."_INSTRS");

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

    printf(HEADER "WRITE_INSTR_TO_SCRATCH_SPACE(%#x);", $cur_opcode);

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

# clean up
system("rm ./dis");
system("rm ./$ARGV[0]");
