using System;
using System.Diagnostics;
using System.Linq;
using EyeStepPackage;
using System.Threading;

namespace U_Dumper
{
    public class Program
    {
        static Stopwatch Watch = new Stopwatch();

        public static int AddyCount;
        public static int OffsetCount;

        static void LogFunction(string Fname, int Address)
        {
            int Space = 20 - Fname.Length;

            Console.Write(Fname);
            for (int i = 0; i < Space; i++) Console.Write(" ");
            Console.Write(": 0x" + Address.ToString("X8").Remove(0, 1) + " " + Environment.NewLine);
            AddyCount = AddyCount + 1;
        }

        static void LogOffset(string Fname, int Offset)
        {
            int Space = 20 - Fname.Length;

            Console.Write(Fname);
            for (int i = 0; i < Space; i++) Console.Write(" ");
            Console.Write(Offset + " " + Environment.NewLine);
            OffsetCount = OffsetCount + 1;
        }
        static void Main()
        {
            Console.Title = "U_Dumper V4";
            Console.WindowWidth = 120;
            Console.WindowHeight = 30;
            Console.SetWindowPosition(0, 0);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n   Credits To U_M9 / Sard\n");

            Process[] getRobloxProcess = Process.GetProcessesByName("Windows10Universal");

            if (getRobloxProcess.Length > 0)
            {
                EyeStep.open("Windows10Universal.exe");
                var random_instruction = EyeStep.read(EyeStep.base_module + 0x1027).data;
                Watch.Start();
                Console.WriteLine("\n   Roblox Found. Extracting...\n");

                var lua_vm_load = scanner.scan_xrefs("oldResult, moduleRef  = ...", 1).Last();
                var lua_vm_load_calls = util.getCalls(util.getPrologue(lua_vm_load)); //17

                var get_scheduler = util.getPrologue(scanner.scan_xrefs("LuauWatchdog", 1).Last());
                var get_scheduler_calls = util.getCalls(get_scheduler); //2

                var task_defer = util.getPrologue(scanner.scan_xrefs("Maximum re-entrancy depth (%i) exceeded calling task.defer", 1).Last());
             
                var task_spawn = util.getPrologue(scanner.scan("55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 EC 56 57 50 8D 45 F4 64 A3 ?? ?? ?? ?? 8B 75 08 C7 45 E8 ?? ?? ?? ??").Last());

                var pseudo2addr = util.getPrologue(scanner.scan("8B C1 81 FA ?? ?? ?? ?? 74 ?? 56").Last());

                var luao_nil_object = util.getPointers(util.getPrologue(scanner.scan("?? ?? ?? ?? 83 7F 0C ?? 0F 84 ?? ?? ?? ?? 83 7F 0C ?? 0F 84 ?? ?? ?? ?? 8B 8D A4 FE FF FF").Last()));
                
                var print = util.getPrologue(scanner.scan_xrefs("Current identity is %d", 1).Last());
                var print_calls = util.getCalls(print); //2

                var global_state = util.prevCall(scanner.scan_xrefs("Script Start", 1).Last());

                var pushkclosure = util.getPrologue(scanner.scan("55 8B EC 53 56 8B D9 8B 73 10").Last());


                //OFFSETS LOCATIONS

                //lua state
                var lua_state_top = scanner.scan("8B 4F 14 8D 77 10 8B C1").Last();
                var lua_state_top_read = EyeStep.read(lua_state_top); //2
                int lua_state_top_offset = lua_state_top_read.bytes[2];

                var lua_state_base = scanner.scan("2B 47 08 C1 F8 ?? C7 41 0C ?? ?? ?? ??").Last();
                var lua_state_base_read = EyeStep.read(lua_state_base); //2
                int lua_state_base_offset = lua_state_base_read.bytes[2];

                var lua_state_extra_space = scanner.scan("8B 76 48 EB ??").Last();
                var lua_state_extra_space_read = EyeStep.read(lua_state_extra_space); //2
                int lua_state_extra_space_offset = lua_state_extra_space_read.bytes[2];

                var lua_state_identity = scanner.scan("89 46 30 5F 5E 5B").Last();
                var lua_state_identity_read = EyeStep.read(lua_state_identity); //2
                int lua_state_identity_offset = lua_state_identity_read.bytes[2];

                var lua_state_identity_2 = scanner.scan("0F 11 46 18 57").Last();
                var lua_state_identity_read_2 = EyeStep.read(lua_state_identity_2); //2
                int lua_state_identity_offset_2 = lua_state_identity_read_2.bytes[2];



                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\n Found Addresses");
                Console.WriteLine("\n\n");
                Console.ForegroundColor = ConsoleColor.Green;

                Console.WriteLine("\n RASLR");
                LogFunction("get_scheduler ", util.raslr(get_scheduler_calls[2]));
                LogFunction("task_defer ", util.raslr(task_defer));
                LogFunction("task_spawn ", util.raslr(task_spawn));
                LogFunction("lua_vm_load ", util.raslr(lua_vm_load_calls[17]));
                LogFunction("print", util.raslr(print_calls[3]));
                LogFunction("global_state", util.raslr(global_state));
                LogFunction("pseudo2addr ", util.raslr(pseudo2addr));
                LogFunction("pushkclosure ", util.raslr(pushkclosure));

                Console.ForegroundColor = ConsoleColor.Yellow;

                Console.WriteLine("\n ASLR");
                LogFunction("get_scheduler ", util.raslr(get_scheduler_calls[2]) - 0x400000);
                LogFunction("task_defer ", util.raslr(task_defer) - 0x400000);
                LogFunction("task_spawn ", util.raslr(task_spawn) - 0x400000);
                LogFunction("lua_vm_load ", util.raslr(lua_vm_load_calls[17]) - 0x400000);
                LogFunction("print", util.raslr(print_calls[3]) - 0x400000);
                LogFunction("global_state", util.raslr(global_state) - 0x400000);
                LogFunction("pseudo2addr ", util.raslr(pseudo2addr) - 0x400000);
                LogFunction("pushkclosure ", util.raslr(pushkclosure) - 0x400000);
                
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("\n\n OFFSETS" );

                LogOffset("lua_state_top", lua_state_top_offset);
                LogOffset("lua_state_base", lua_state_base_offset);


                LogOffset("identity (For Setting LuaState Level)", lua_state_identity_offset_2);
                LogOffset("identity (For Getting LuaState)", lua_state_identity_offset);

                LogOffset("extra_space", lua_state_extra_space_offset);

                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("\n\n");
                Watch.Stop();
                Console.WriteLine("  Scanned " + AddyCount + " Addresses, " + OffsetCount + " Offsets, \nTook " + Watch.ElapsedMilliseconds + "ms");
                Process[] workers = Process.GetProcessesByName("Windows10Universal");
                Console.WriteLine("  Press Enter To Exit...");
                Console.ReadLine();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\n  Roblox Not Found...\n");
                Thread.Sleep(2000);
                Environment.Exit(0);
                Console.ReadLine();
            }

        }
    }
}


